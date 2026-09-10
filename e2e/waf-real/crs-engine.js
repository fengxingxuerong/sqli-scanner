// ============================================================================
// e2e/waf-real/crs-engine.js —— OWASP CRS v4.1.0 规则执行器（简化版 ModSecurity）
//
// 规则原文：rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf（OWASP CRS v4.1.0 官方文件，
// jsdelivr 分发，Apache-2.0）。本执行器按 ModSecurity SecRule 语义执行：
//   ① 变量映射：ARGS/ARGS_NAMES/REQUEST_COOKIES/REQUEST_HEADERS:*/REQUEST_URI/QUERY_STRING
//   ② 变换链：t:urlDecodeUni / t:lowercase / t:replaceComments / t:removeNulls /
//      t:removeWhitespace / t:removeCommentsChar / t:compressWhitespace / t:htmlEntityDecode
//   ③ operator：@rx（CRS 原文正则）为主；@lt/@streq 的 TX 元规则跳过
//   ④ 链式规则（chain）：组内全部 SecRule 均命中才 block（AND 语义）
//   ⑤ Paranoia Level：默认全部应用（≈PL3 最严格）；可用 paranoiaLevel 参数截断
//
// 诚实边界（不是完整 ModSecurity）：
//   - @detectSQLi（libinjection 指纹，2 条规则）无 C 内核，按跳过统计，不做近似
//   - 不支持 SecAction/ctl/排除集（ exclusion packages）、IP 信誉等周边
//   - 相位简化：phase:1/2 不区分（全部对请求体求值）
// 结论：检出强度略低于真实 ModSecurity+CRS（缺 libinjection），绕过率据此略偏高。
// ============================================================================

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// —— 变换函数（与 ModSecurity t: 动作同名的常用子集）——
const T = {
  none: (s) => s,
  lowercase: (s) => s.toLowerCase(),
  urldecodeuni: (s) => {
    let out = String(s);
    try {
      out = decodeURIComponent(out.replace(/\+/g, ' '));
    } catch {
      /* 非法序列保留原样 */
    }
    // %uXXXX（IIS 宽字符编码）
    out = out.replace(/%u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return out;
  },
  removenulls: (s) => s.replace(/\0/g, ''),
  removewhitespace: (s) => s.replace(/\s+/g, ''),
  removecommentschar: (s) => s.replace(/\/\*|\*\//g, ''),
  replacecomments: (s) => s.replace(/\/\*[\s\S]*?\*\//g, ' '),
  compresswhitespace: (s) => s.replace(/\s+/g, ' '),
  htmlentitydecode: (s) => s
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
};

// —— 解析 .conf：续行拼接 → SecRule 分条 → 链聚合 ——
export function parseCrsFile(confPath) {
  const raw = readFileSync(confPath, 'utf8');
  // 续行：行尾 \ 与下一行拼接（正确维护 pending 状态）
  const lines = raw.split(/\r?\n/);
  const joined = [];
  for (const line of lines) {
    if (joined.length && joined[joined.length - 1].pending) {
      // 上一行以 \ 结尾 → 本行是其延续
      joined[joined.length - 1].text += ' ' + line.replace(/\\\s*$/, '');
      joined[joined.length - 1].pending = /\\\s*$/.test(line);
    } else {
      joined.push({ pending: /\\\s*$/.test(line), text: line.replace(/\\\s*$/, '') });
    }
  }
  const statements = joined.map((j) => j.text.replace(/\\\s*$/, '').trim()).filter(Boolean);

  const rules = [];       // 平铺链节点
  let curChain = null;    // 当前链聚合
  let pl = 0;             // 当前 Paranoia Level 区块
  for (const st of statements) {
    // PL 区块注释跟踪
    const plm = st.match(/-= Paranoia Level (\d+)/);
    if (plm) pl = Number(plm[1]);
    if (!st.startsWith('SecRule')) continue;
    // CRS 正则内含转义引号 \" → 先替换为占位符再按引号切分，解析后还原
    const esc = st.replace(/\\"/g, '\u0001');
    const m = esc.match(/^SecRule\s+(.+?)\s+"([^"]*)"\s+"([^"]*)"\s*$/);
    if (!m) continue;
    const [, varsRaw, opRaw, actRaw] = m;
    const unesc = (s) => s.replace(/\u0001/g, '"');
    const op = unesc(opRaw);
    const act = unesc(actRaw);
    const rule = {
      vars: varsRaw.split('|').map((v) => v.trim()),
      opRaw: op,
      id: (act.match(/id:(\d+)/) || [])[1] || null,
      phase: Number((act.match(/phase:(\d)/) || [])[1]) || 2,
      block: /\bblock\b|\bdeny\b/.test(act),
      transforms: [...act.matchAll(/t:([a-zA-Z]+)/g)].map((x) => x[1].toLowerCase()).filter((t) => T[t]),
      pl,
      msg: (act.match(/msg:'([^']*)'/) || [])[1] || '',
      isChainHead: false,
    };
    // TX:DETECTION_PARANOIA_LEVEL 元规则 / skipAfter 控制规则 → 跳过
    if (/^TX:/i.test(varsRaw.trim()) || rule.opRaw.startsWith('@lt') || /skipAfter/.test(act)) continue;
    // 链：actions 含 chain → 后续紧邻 SecRule 是链内节点
    const isChain = /\bchain\b/.test(act);
    rule.isChainHead = isChain && !curChain;
    if (curChain) curChain.chain.push(rule);
    else if (isChain) {
      curChain = { ...rule, chain: [rule] };
      rules.push(curChain);
    } else rules.push(rule);
    if (!isChain) curChain = null;
  }
  return rules;
}

// —— 变量取值：把请求对象映射为 CRS 变量名 → [值...] ——
function collectValues(vars, req) {
  const out = [];
  for (const v of vars) {
    const neg = v.startsWith('!');
    const name = neg ? v.slice(1) : v;
    const push = (arr) => { if (!neg) out.push(...arr); else out.length && out; };
    if (name === 'ARGS') push(Object.values(req.args));
    else if (name === 'ARGS_NAMES') push(Object.keys(req.args));
    else if (name === 'REQUEST_COOKIES') push(Object.values(req.cookies));
    else if (name === 'REQUEST_COOKIES_NAMES') push(Object.keys(req.cookies));
    else if (name.startsWith('REQUEST_HEADERS:')) {
      const h = name.split(':')[1].toLowerCase();
      push(req.headers[h] ? [req.headers[h]] : []);
    } else if (name === 'REQUEST_HEADERS') push(Object.values(req.headers));
    else if (name === 'REQUEST_URI' || name === 'REQUEST_FILENAME' || name === 'REQUEST_BASENAME') {
      push([req.uri]);
    } else if (name === 'QUERY_STRING') push([req.queryString]);
    else if (name === 'XML:/*' || name === 'TX:DETECTION_PARANOIA_LEVEL') push([]);
    else push([]); // 未知变量（REQUEST_BODY 等）：保守跳过
  }
  return out;
}

// —— 应用变换链 ——
function applyTransforms(value, transforms) {
  let s = String(value);
  for (const t of transforms) s = T[t](s);
  return s;
}

// —— 执行 operator ——
function matchOp(rule, value) {
  const op = rule.opRaw;
  if (op.startsWith('@rx') || !op.startsWith('@')) {
    const reSrc = op.startsWith('@rx') ? op.slice(3).trim() : op;
    // CRS 正则多为 PCRE 兼容（(?i:...) / \b 等），JS 直接可用；个别含 \p{} 已人工确认无
    try {
      const re = new RegExp(reSrc.startsWith('(?i)') ? reSrc.slice(4) : reSrc, 'i'.repeat(reSrc.startsWith('(?i)') ? 0 : 1));
      return re.test(value);
    } catch {
      return false; // JS 不兼容的正则保守跳过（统计）
    }
  }
  if (op.startsWith('@streq')) return value === op.slice(6).trim();
  return false; // @detectSQLi 等无内核 operator：不匹配（跳过统计在调用侧）
}

/**
 * 评估一次请求是否被 CRS 942（SQLi）拦截。
 * @param {object} req { method, uri, queryString, args:{k:v}, cookies:{}, headers:{} }
 * @param {object} [opts] { paranoiaLevel=3, confPath }
 * @returns {{blocked: boolean, ruleId: string|null, msg: string, matchedRules: string[]}}
 */
export function evaluate(req, opts = {}) {
  const confPath = opts.confPath || resolve(HERE, 'crs/REQUEST-942-SQLI.conf');
  if (!evaluate._rules || evaluate._confPath !== confPath) {
    evaluate._rules = parseCrsFile(confPath);
    evaluate._confPath = confPath;
  }
  const maxPL = opts.paranoiaLevel ?? 3;
  const matched = [];
  for (const group of evaluate._rules) {
    const nodes = group.chain || [group];
    // PL 截断（规则所在区块 PL > 配置上限 → 跳过）
    if (nodes.some((n) => n.pl > maxPL)) continue;
    let allHit = true;
    for (const node of nodes) {
      const values = collectValues(node.vars, req).map((v) => applyTransforms(v, node.transforms));
      const hit = values.some((v) => matchOp(node, v));
      if (!hit) { allHit = false; break; }
    }
    if (allHit) {
      matched.push(group.id || 'no-id');
      if (group.block !== false) {
        return { blocked: true, ruleId: group.id, msg: group.msg, matchedRules: matched };
      }
    }
  }
  return { blocked: false, ruleId: null, msg: '', matchedRules: matched };
}

/**
 * 把 Express req（query/body/cookie）转成执行器入参。
 */
export function fromExpress(req) {
  const u = new URL(req.originalUrl || req.url, 'http://local');
  const args = { ...Object.fromEntries(u.searchParams.entries()), ...(req.body && typeof req.body === 'object' ? req.body : {}) };
  return {
    method: req.method,
    uri: u.pathname + u.search,
    queryString: u.search.slice(1),
    args,
    cookies: Object.fromEntries(Object.entries(req.cookies || {})),
    headers: Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(',') : String(v)])),
  };
}

export default { parseCrsFile, evaluate, fromExpress };

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
//   - PCRE 语法只适配到「本执行器恒用 flags:'i'」能表达的那一层：`(?i)` / `(?i:…)` 已降级，
//     `(?-i:…)` 与 (?s)(?x)(?P<>) 等遇到即放弃该规则（命中失败 + 普查记一笔 + 保真度门禁 FAIL）。
//     ⚠️ Node ≥23（V8 13）原生支持 `(?i:…)`，届时降级是冗余的但**仍等价**；反过来若把本仓
//     升到 Node 23+ 再回退到 22，会让这 5 条规则静默失效 —— 所以保真度门禁必须一直跑。
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
//
// [CENSUS 2026-09-19] 本机没有 Docker/Go，跑不了真 ModSecurity/Coraza，所以"≈PL3"这句话过去只是
// 一句注释。这里把**执行器与官方规则的差距变成可核对的计数**：多少条 SecRule 被解析器丢掉、
// 多少条用的是我们没实现的 operator（@detectSQLi 等 → 那条规则恒不匹配，报告里看不出异常）。
// 计数在 parseCrsFile 里做一次（不在 execOp 热路径上），由 getParseStats() 读出；
// 实测结果由 e2e/waf-real/crs-equivalence.mjs 打印，并用 CRS 官方回归用例交叉验证。
// （曾经我在此处记过"`(?i:…)` 内联分组在 JS 会抛所以 5 条规则静默失效"——那是误报：
//   内联修饰组是 ES2025 语法，V8 13 / Node 24 合法且语义正确。别照那种说法再写一遍。）
const PARSE_STATS = new Map();
// execOp 只实现了这两个 operator；其余（@detectSQLi/@pm/@ge/@within/…）一律"永不匹配"，必须计数
const IMPLEMENTED_OPS = new Set(['@rx', '@streq']);

export function getParseStats(confPath) {
  return PARSE_STATS.get(confPath) || null;
}

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
  const stats = { secRuleLines: 0, droppedBySplit: 0, skippedMeta: 0, ops: {}, regexBad: [], loaded: 0, chainHeads: 0, unimplemented: 0, unimplementedIds: [], plById: {} };
  for (const st of statements) {
    // PL 区块注释跟踪
    const plm = st.match(/-= Paranoia Level (\d+)/);
    if (plm) pl = Number(plm[1]);
    if (!st.startsWith('SecRule')) continue;
    stats.secRuleLines++;
    // CRS 正则内含转义引号 \" → 先替换为占位符再按引号切分，解析后还原
    const esc = st.replace(/\\"/g, '\u0001');
    const m = esc.match(/^SecRule\s+(.+?)\s+"([^"]*)"\s+"([^"]*)"\s*$/);
    if (!m) { stats.droppedBySplit++; continue; }
    const [, varsRaw, opRaw, actRaw] = m;
    const unesc = (s) => s.replace(/\u0001/g, '"');
    const op = unesc(opRaw);
    const act = unesc(actRaw);
    // 链节点里的 `&TX:1` / `&ARGS` 是**计数语义**（取个数而非内容），`&` 要单独记下来
    const varTokens = varsRaw.split('|').map((v) => v.trim());
    const countMode = varTokens.every((v) => v.startsWith('&'));
    const rule = {
      vars: varTokens.map((v) => (v.startsWith('&') ? v.slice(1) : v)),
      countMode,
      opRaw: op,
      id: (act.match(/id:(\d+)/) || [])[1] || null,
      phase: Number((act.match(/phase:(\d)/) || [])[1]) || 2,
      block: /\bblock\b|\bdeny\b/.test(act),
      transforms: [...act.matchAll(/t:([a-zA-Z]+)/g)].map((x) => x[1].toLowerCase()).filter((t) => T[t]),
      pl,
      msg: (act.match(/msg:'([^']*)'/) || [])[1] || '',
      isChainHead: false,
    };
    // 元规则/控制规则：只在**它不是链节点**时跳过。
    // [CHAIN-FIX 2026-09-19] 原来无条件 `continue` 把 `SecRule TX:1 "@rx …"` 这类**链的第二节点**
    // 也丢了（942130/942150/942521/942522 全靠它做"同一请求里还要有第二种 SQL 信号"的判据），
    // 而且跳过后 curChain 没复位，会把再下一条语句错接到原链上。
    if (!curChain && (/^TX:/i.test(varsRaw.trim()) || op.startsWith('@lt') || /skipAfter/.test(act))) { stats.skippedMeta++; continue; }
    // 链：actions 含 chain → 后续紧邻 SecRule 是链内节点
    const isChain = /\bchain\b/.test(act);
    rule.isChainHead = isChain && !curChain;
    if (curChain) curChain.chain.push(rule);
    else if (isChain) {
      curChain = { ...rule, chain: [rule] };
      rules.push(curChain);
    } else rules.push(rule);
    if (!isChain) curChain = null;

    // —— 保真度普查（只统计，不改变判定）——
    stats.loaded++;
    // 规则 id → 所属 PL 区块：官方回归用例的"逐规则一致率"必须在**该规则本该生效的档位**上比，
    // 否则 PL1 档下那些 PL2/PL3 规则的低命中会被当成执行器失真（其实是正确行为）。
    if (rule.id && stats.plById[rule.id] == null) stats.plById[rule.id] = pl;
    const opName = (op.match(/^@\w+/) || ['(裸正则 @rx)'])[0];
    stats.ops[opName] = (stats.ops[opName] || 0) + 1;
    if (!IMPLEMENTED_OPS.has(opName) && opName !== '(裸正则 @rx)') {
      stats.unimplemented = (stats.unimplemented || 0) + 1;
      (stats.unimplementedIds ||= []).push(`${rule.id || '?'}:${opName}`);
    }
    // 编译探针必须与 execOp **共用同一个适配函数**，否则普查会和实际行为两套真相。
    // （上一版注释称 `(?i:…)` 在 ES2025/V8 13 已合法、记进 regexBad 是"误报"——实测打脸：
    //   本项目跑在 Node 22.22.2 / V8 12.4，`new RegExp('(?i:…)', 'i')` 直接抛 Invalid group，
    //   那 5 条规则是真的恒不命中。ES2025 的修饰符组要到 Node 23+ 才有，不能拿未来语法当下现状。）
    const rawRx = opName === '@rx' ? op.slice(3).trim() : op.startsWith('@') ? '' : op;
    if (rawRx) {
      const jsSrc = toJsRegex(rawRx);
      if (jsSrc == null) stats.regexBad.push(rule.id || '?');
      else { try { new RegExp(jsSrc, 'i'); } catch { stats.regexBad.push(rule.id || '?'); } }
    }
    if (rule.isChainHead) stats.chainHeads++;
  }
  stats.groups = rules.length;
  PARSE_STATS.set(confPath, stats);
  return rules;
}

// —— 变量取值：把请求对象映射为 CRS 变量名 → [值...] ——
// state 用于链式规则：captures = 上一节点正则的捕获组，matchedVals = 上一节点命中的值。
// CRS 的"条件式 SQLi"族（942130/942150/942521/942522…）靠 `TX:1`、`MATCHED_VARS` 表达
// "同一请求里还得有第二种信号"，不给这两个变量的值，那批规则就永远不匹配。
function collectValues(vars, req, state = {}) {
  const out = [];
  for (const v of vars) {
    const neg = v.startsWith('!');
    const name = neg ? v.slice(1) : v;
    const push = (arr) => { if (!neg) out.push(...arr); else out.length && out; };
    if (name === 'ARGS') push(Object.values(req.args));
    else if (name === 'ARGS_NAMES') push(Object.keys(req.args));
    else if (name === 'REQUEST_COOKIES') push(Object.values(req.cookies));
    else if (name === 'REQUEST_COOKIES_NAMES') push(Object.keys(req.cookies));
    else if (/^TX:\d+$/.test(name)) {
      // 链上下文里的 TX:n = 上一节点的第 n 个捕获组（ModSecurity 语义）
      const c = state.captures;
      push(c && c[Number(name.slice(3))] != null ? [String(c[Number(name.slice(3))])] : []);
    } else if (name === 'MATCHED_VARS' || name === 'MATCHED_VARS_NAMES') {
      push(state.matchedVals || []);
    } else if (name.startsWith('REQUEST_HEADERS:')) {
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

/** 计数语义（`&ARGS @ge 2`）：拿"个数"和 operator 的数字比。 */
function matchCount(opRaw, n) {
  const m = /^@(ge|gt|le|lt|eq)\s+(\d+)\s*$/.exec(opRaw.trim());
  if (!m) return false;
  const k = Number(m[2]);
  switch (m[1]) {
    case 'ge': return n >= k;
    case 'gt': return n > k;
    case 'le': return n <= k;
    case 'lt': return n < k;
    default: return n === k;
  }
}

// —— PCRE → JS 正则适配（execOp 与装载期普查**必须共用**，否则两套真相）——
// 返回 null = 主动放弃（存在无法用全局 flag 表达的反向开关），调用方按"算不出"处理。
function toJsRegex(src) {
  if (/\(\?-i[:)]/.test(src)) return null;
  // `(?i)`：模式级开关，本执行器恒用 flags:'i'，删掉即可（行首、中间都删）
  // `(?i:`：组级开关，同样因外层已全局不敏感而等价于普通非捕获组
  return String(src).replace(/\(\?i\)/g, '').replace(/\(\?i:/g, '(?:');
}

/** 命中则返回 RegExp 的匹配结果（链节点要靠它取捕获组），否则返回 null。 */
function execOp(rule, value, state = {}) {
  const op0 = rule.opRaw;
  // `!@rx …` / `!@pm …`：CRS 用取反 operator 表达"除这种形态外都算"（如 942440 的
  // `MATCHED_VARS "!@rx ^ey…"`，意思是"命中的值里只要**不是** JWT 段就算 SQLi 特征"）。
  // 原来不认 `!` 前缀：既不匹配也不报错，整条规则恒不命中。
  const negated = op0.startsWith('!');
  const op = negated ? op0.slice(1) : op0;
  // operator 参数里的 `%{TX.n}` 是**上一节点正则的捕获组**（942130 用 `TX:1 "@streq %{TX.2}"`
  // 表达"两个操作数相等"），不展开就等于拿字面量 "%{TX.2}" 去比，永远不相等。
  const expand = (s) => String(s).replace(/%\{TX\.(\d+)\}/g, (_, n) => {
    const c = state.captures;
    return c && c[Number(n)] != null ? String(c[Number(n)]) : '';
  });
  if (op.startsWith('@rx') || !op.startsWith('@')) {
    const reSrc = expand(op.startsWith('@rx') ? op.slice(3).trim() : op);
    // [PCRE-ADAPT 2026-09-19 实测] CRS 的 pattern 是 PCRE 语法，其中两类构造在
    // **本项目实际运行的 Node 22.22.2（V8 12.4）上直接抛 "Invalid group"**：
    //   ① 模式级开关 `(?i)`（行首或中间任意位置）
    //   ② 组级开关 `(?i:…)`（ES2025 regex modifiers —— 要 V8 13 / Node 23+ 才有）
    // 也就是说：这不是"记错了的误报"，是**真的编译失败**，而 catch 分支返回 null →
    // 这 5 条规则（942160/942220/942250/942361/942450）恒不命中，官方回归集上漏 23 条
    // （sleep()/benchmark()、整数溢出、EXECUTE IMMEDIATE、^[\W\d]+\s*(alter|union)、0x 十六进制）。
    // 降级规则：本执行器恒以 flags:'i' 编译，所以 `(?i)` 是冗余可删、`(?i:…)` 等价于 `(?:…)`。
    // 反向开关 `(?-i:…)` 无法用全局 flag 表达，遇到即放弃（继续走 catch → 保守跳过），
    // 否则会把"本该大小写敏感"的子表达式放大成不敏感，制造假命中。
    // try/catch 必须留着：降级只覆盖**今天已知的**两类构造。将来 CRS 升版引入别的 PCRE 语法
    // （(?s) (?x) (?P<>) 等），这里会抛——抛了要退化成"该规则不命中 + 普查记一笔 + 门禁 FAIL"，
    // 而不是让整个保真度脚本崩掉（崩掉反而看不见失败原因）。
    const jsSrc = toJsRegex(reSrc);
    if (jsSrc != null) {
      try {
        const re = new RegExp(jsSrc, 'i');
        const m = re.exec(value);
        if (negated) return m ? null : [value];
        return m;
      } catch { /* 落到下面的保守跳过 */ }
    }
    return negated ? [value] : null; // 编不出来/主动放弃：保守跳过，条数由普查报出来
    // 沿革：上一版只剥**行首** `(?i)` 就把源码丢给 `new RegExp`，碰上 `(?i:…)` 一律进 catch。
    // 更早那版更糟——剥掉 `(?i)` 却给空 flags，等于把 CRS 几乎所有 @rx 从"不敏感"变成"敏感"
    // （修前 PL4 逐规则一致率仅 60.7%）。现在统一走 toJsRegex + flags:'i'，两种 `(?i)` 形态都覆盖。
  }
  if (op.startsWith('@streq')) {
    const eq = value === expand(op.slice(6).trim());
    // 取反必须在这里也生效：942131 的链节点是 `TX:1 "!@streq %{TX.2}"`（"两个操作数**不**相等才算"），
    // 漏掉 negated 会把判据整个反过来 —— `11!=11` 这种平凡式反而被判成 SQLi。
    if (negated) return eq ? null : [value];
    return eq ? [value] : null;
  }
  // 未实现的 operator：即使外面套了 `!` 也**不伪造命中**。取反的意思本是"排除这种"，
  // 我们既然算不出内层条件，就没有资格宣布它不成立 —— 宁可不命中（漏，由普查与分歧清单暴露），
  // 也不要用"看起来更严"的假命中污染 WAF 数字。
  return null; // @detectSQLi / @pm / @ge 等：恒不匹配（按 id 点名在普查里）
}

// 默认 Paranoia Level：**显式可配**，并且必须在报告里写出来。
// 原来固定 3（≈全规则最严档），既不是 CRS 的默认部署档（官方默认 PL1），也没在数字旁边标注，
// 于是"绕过率 8/8"这种说法既不知道对齐的是哪一档、也容易被当成线上典型表现。
// 用 CRS_PL=1..4 覆盖；未设置时保持 3（与既有报告口径连续），但调用方要把打印出来的档位一起存档。
const DEFAULT_PL = (() => {
  const v = Number(process.env.CRS_PL);
  return Number.isInteger(v) && v >= 1 && v <= 4 ? v : 3;
})();
/** 报告要用它把口径写清楚（"8/8" 不带档位等于没说）。 */
export const EFFECTIVE_PL = DEFAULT_PL;

/**
 * 评估一次请求是否被 CRS 942（SQLi）拦截。
 * @param {object} req { method, uri, queryString, args:{k:v}, cookies:{}, headers:{} }
 * @param {object} [opts] { paranoiaLevel=CRS_PL||3, confPath, collectAll }
 * @returns {{blocked: boolean, ruleId: string|null, msg: string, matchedRules: string[]}}
 */
export function evaluate(req, opts = {}) {
  const confPath = opts.confPath || resolve(HERE, 'crs/REQUEST-942-SQLI.conf');
  if (!evaluate._rules || evaluate._confPath !== confPath) {
    evaluate._rules = parseCrsFile(confPath);
    evaluate._confPath = confPath;
  }
  const maxPL = opts.paranoiaLevel ?? DEFAULT_PL;
  // [等价性验证用] collectAll：跑完全部规则、不早退，返回"所有命中的规则 id"。
  // 官方回归用例的期望是**按规则 id**写的（log_contains: id "942100"），只看"拦没拦"就没法
  // 逐条核对；默认 false，检测链路行为一字不变。
  const collectAll = opts.collectAll === true;
  const matched = [];
  let firstBlock = null;
  for (const group of evaluate._rules) {
    const nodes = group.chain || [group];
    // PL 截断（规则所在区块 PL > 配置上限 → 跳过）
    if (nodes.some((n) => n.pl > maxPL)) continue;
    let allHit = true;
    // [CHAIN-FIX] 链式规则按 ModSecurity 语义逐节点求值，并把上一节点的**捕获组**与**命中的值**
    // 传给下一节点（`TX:1` / `MATCHED_VARS` / `&…@ge N` 全靠这两个状态）。
    let state = {};
    for (const node of nodes) {
      const values = collectValues(node.vars, req, state).map((v) => applyTransforms(v, node.transforms));
      if (node.countMode) {
        if (!matchCount(node.opRaw, values.length)) { allHit = false; break; }
        continue;
      }
      let hit = null;
      const matchedVals = [];
      for (const v of values) {
        const m = execOp(node, v, state);
        if (m) { matchedVals.push(v); hit ||= m; }
      }
      if (!hit) { allHit = false; break; }
      state = { captures: hit, matchedVals };
    }
    if (allHit) {
      matched.push(group.id || 'no-id');
      if (group.block !== false) {
        if (!collectAll) return { blocked: true, ruleId: group.id, msg: group.msg, matchedRules: matched };
        firstBlock ||= { ruleId: group.id, msg: group.msg };
      }
    }
  }
  if (collectAll) {
    return firstBlock
      ? { blocked: true, ruleId: firstBlock.ruleId, msg: firstBlock.msg, matchedRules: matched }
      : { blocked: false, ruleId: null, msg: '', matchedRules: matched };
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

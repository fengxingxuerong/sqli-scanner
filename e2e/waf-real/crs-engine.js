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
// [2026-09-24] `t:utf8toUnicode` —— 按实测计数：942 有 3 条规则声明它（942100/942101/942120），
// 930 有 4 条。它此前被**两重**原因丢掉：① T 里没实现；② 取名正则会砍在数字上（见
// declaredTransforms）。只修①不够——修完①普查归零、取值链照旧丢，这才是最难查的那一步。
// 做的事：把百分号形态的 UTF-8 字节序列**折成一个码点字符**，让后面那条
// `t:urlDecodeUni` 看得到真字符。之所以作用在百分号形态上：CRS 把本变换排在 urlDecodeUni
// **之前**，而 `%c0%af`（`/`）、`%c1%bc`（`|`）这类超长编码正是绕 WAF 的经典写法 ——
// 不先折叠，紧随其后的规则正则永远看不见被藏起来的字符。
// 规范序列（`%c3%a9` → é）一并折叠，与 ModSecurity 的落点一致：它折成 `%u00e9` 后
// urlDecodeUni 同样给出 U+00E9，最终字符相同。
//
// ⚠ 必须**逐字节推进**，不能写成 `/((?:%XX){2,4})/` 一次吞掉 2–4 段：
//   贪婪量词会把**下一个序列的字节**一起吃进去（`%c1%bc%c1%bc` 本应是 `||`，
//   一次匹配只解出 2 字节、剩下 2 字节被丢弃 ⇒ 变成单个 `|` ⇒ 942120 该中不中）。
//   这是本机实测出来的（HEAD 版本对新实现做差分，五条 overlong 用例改前改后完全一致）。
function utf8ToUnicode(s) {
  const str = String(s);
  const BYTE = /%([0-9A-Fa-f]{2})/g; // 一个百分号字节 token
  let out = '';
  let pos = 0;
  while (pos < str.length) {
    BYTE.lastIndex = pos;
    const m = BYTE.exec(str);
    if (!m) { out += str.slice(pos); break; }
    const lead = parseInt(m[1], 16);
    const need = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 0;
    const afterLead = m.index + m[0].length;
    // 单字节（ASCII）形态不属于本变换的职责：原样放过，继续找下一个
    if (!need) { out += str.slice(pos, afterLead); pos = afterLead; continue; }
    const bytes = [lead];
    let cur = afterLead;
    let valid = true;
    for (let k = 1; k < need; k++) {
      BYTE.lastIndex = cur;
      const n = BYTE.exec(str);
      if (!n || n.index !== cur) { valid = false; break; } // 后续字节不紧邻 ⇒ 不是同一序列
      const b = parseInt(n[1], 16);
      if ((b & 0xc0) !== 0x80) { valid = false; break; } // 不是合法 continuation 字节
      bytes.push(b);
      cur += n[0].length;
    }
    if (!valid) { out += str.slice(pos, afterLead); pos = afterLead; continue; }
    let cp = lead & (0xff >> (need + 1));
    for (let k = 1; k < need; k++) cp = (cp << 6) | (bytes[k] & 0x3f);
    // 只拒"非法码点"（越界、代理区）。绝不能拒超长形态：`cp < 该长度的规范最小值`
    // （`%c0%af` 解出 0x2f < 0x80）正是本变换唯一要抓的东西，写反过一次 ⇒ 变换对攻击
    // 形态完全不干活，而普查里 `utf8tounicode` 已消失 ⇒ 数字看着"已实现"，实则空壳。
    // 同理不能加 `cp < 0x80` 短路：3 字节超长解出 ASCII（`%e0%80%af` → `/`）是同一类绕过。
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      out += str.slice(pos, afterLead);
      pos = afterLead;
      continue;
    }
    out += str.slice(pos, m.index) + String.fromCodePoint(cp);
    pos = cur; // 只推进到**实际消费掉**的字节之后，剩下的交给下一轮
  }
  return out;
}

const T = {
  utf8tounicode: utf8ToUnicode,
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

/**
 * 从 actions 串里取出规则**声明**的变换名（小写）。
 *
 * 取名语法必须是 `[a-zA-Z0-9]+`：CRS 的 `t:utf8toUnicode` 名字里带数字，
 * 用 `[a-zA-Z]+` 会在 `8` 处截断成 `utf` ⇒ 查不到 T ⇒ 被 `.filter` 静默丢掉，
 * 而普查（本来就是 `[a-zA-Z0-9]+`）却因为"已经注册"而报"无缺失" —— 两边语法不同，
 * 于是出现过一种最难查的状态：报告说缺口已补，实际取值链上那个变换从未生效过。
 * 所以声明侧与普查侧**必须共用这个函数**，不允许再各写一份正则。
 */
function declaredTransforms(act) {
  return [...act.matchAll(/t:([a-zA-Z0-9]+)/g)].map((x) => x[1].toLowerCase());
}

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
// execOp 只实现了这三个 operator；其余（@detectSQLi/@pm/@ge/@within/…）一律"永不匹配"，必须计数。
// @pmFromFile 于 2026-09-25 登记 —— 但登记只是"有资格匹配"，实际能不能匹配取决于词典文件在不在，
// 所以它的缺口不在这里归零，而在 pmLoaded/missingDicts 那一组计数里（见 loadPmDict 注释）。
const IMPLEMENTED_OPS = new Set(['@rx', '@streq', '@pmFromFile']);

/**
 * `@pmFromFile <name>.data` 的词典：按**绝对路径**缓存（同一份词典被 930120/930121 复用）。
 *
 * 语义照 ModSecurity：不敏感**子串**匹配，无词边界（Aho-Corasick 多模式）。所以条目
 * `sys/class` 能命中 `/sys/class` —— 上游词典有意用"最短可辨识路径"，斜杠形态也不统一，
 * 任何"按行首/词边界匹配"的自作聪明都会把召回砍掉。
 *
 * 载入时机在**解析期**而不是 execOp 热路径：这样"文件不在"是一条能当场报出来的配置错误，
 * 而不是让那三条规则静默恒不匹配 —— 后者正是本项目反复出现的失效形状（数字照常产出，
 * 前提却没人看见）。缺文件时记进 `stats.missingDicts` 并保持该规则不命中（宁漏勿假命中）。
 */
const PM_DICT_CACHE = new Map();
function loadPmDict(absPath, stats, ruleId, dictName) {
  stats.pmRefs = (stats.pmRefs || 0) + 1;
  let entries = PM_DICT_CACHE.get(absPath);
  if (entries === undefined) {
    // 缓存里"没有这个键"才代表没读过；读失败也缓存 null，避免每次解析都重复撞文件系统
    try {
      entries = readFileSync(absPath, 'utf8')
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'))
        .map((l) => l.toLowerCase());
    } catch {
      entries = null;
    }
    PM_DICT_CACHE.set(absPath, entries);
  }
  // 文件级计数按**本次解析**去重（stats.pmFiles 随每次 parseCrsFile 新建）：
  // 词典缓存是模块级的，若把计数挂在"缓存未命中"分支上，同一进程里第二次解析同一份
  // conf 就会报出"载入 0 个文件、合计 0 条条目"—— 数字在撒谎，却撒得看不出来。
  const seen = (stats.pmFiles ||= new Set());
  if (!seen.has(absPath)) {
    seen.add(absPath);
    stats.pmLoaded = (stats.pmLoaded || 0) + (entries ? 1 : 0);
    stats.pmEntries = (stats.pmEntries || 0) + (entries ? entries.length : 0);
  }
  // 缺失/空词典按**规则**记（两条规则共用一份坏词典 = 两条都恒不匹配，得数得对）
  if (entries && entries.length === 0) (stats.emptyDicts ||= new Set()).add(`${ruleId || '?'}:${dictName}`);
  if (!entries) (stats.missingDicts ||= new Set()).add(`${ruleId || '?'}:${dictName}`);
  return entries;
}

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
  const stats = { secRuleLines: 0, droppedBySplit: 0, skippedMeta: 0, ops: {}, regexBad: [], loaded: 0, chainHeads: 0, unimplemented: 0, unimplementedIds: [], plById: {}, missingDicts: new Set(), emptyDicts: new Set() };
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
      transforms: declaredTransforms(act).filter((t) => T[t]),
      pl,
      msg: (act.match(/msg:'([^']*)'/) || [])[1] || '',
      // [2026-09-24] ctl:ruleRemoveTargetById=<规则id>;<集合>:<参数名>
      // CRS 用它给已知误报开"参数级豁免"（本 vendored conf 里有两条：942441 豁免 fbclid、
      // 942442 豁免 gclid，都指向 942440 的注释符检测）。此前执行器**完全不实现 ctl:**，
      // 于是 crs-known-divergences.json 把 942440-19 记成"依赖参数排除集，而排除集在别的
      // conf 里、本仓没 vendored" —— 那个归因是错的：两条排除规则就在同一份 conf 的
      // 1323/1338 行。真实原因从来只有一个：我们自己没实现。
      ctlRemove: [...act.matchAll(/ctl:ruleRemoveTargetById=(\d+);([A-Za-z_]+):([^,\\'"\s]+)/g)]
        .map((m) => ({ ruleId: m[1], collection: m[2].toUpperCase(), name: m[3] })),
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
    // @pmFromFile 的词典在**解析期**就位。文件名就是 operator 的参数，路径与 conf 同目录
    // （上游 CRS 把 rules/*.conf 与 rules/*.data 放在一起，所以 conf 落在哪、词典就落在哪）。
    if (opName === '@pmFromFile') {
      const dictName = op.slice(opName.length).trim();
      rule.dict = dictName
        ? loadPmDict(resolve(dirname(confPath), dictName), stats, rule.id, dictName)
        : null;
    }
    // [2026-09-24] 变量侧普查，与上面 operator 侧同一套路。
    // 之前变量只有"落不进去就 push([])"的隐式行为，谁不支持没人知道 ——
    // `ARGS_GET:fbclid` 就是例子：两条官方排除规则因此恒不命中，而症状表现为"942440 误报"。
    // 判据与取值**共用 classifyVar**，避免"普查说支持、实际取不到"的两套真相。
    // 变换链也不能静默丢：`.filter(t => T[t])` 只留下认识的变换，缺的那几个**连报错都没有** ——
    // 与变量侧曾经"落到 else 返回空"是同一种失效形状。942 自己就用着 `t:utf8toUnicode`，
    // 而它此前从未进过取值链（取名正则 `[a-zA-Z]+` 在数字 `8` 处截断），意味着
    // "99.3% 一致率"是在缺这个变换的前提下量出来的 —— 这个前提必须能被看见。
    // 取名走 declaredTransforms，与 rule.transforms **同源**，否则会出现"普查说已实现、
    // 取值链其实没跑"的两套真相（本机真踩过一次）。
    for (const nm of declaredTransforms(act)) {
      if (nm === 'none' || T[nm]) continue;
      stats.droppedTransforms = (stats.droppedTransforms || new Set()).add(nm);
    }
    for (const tok of rule.vars || []) {
      const c = classifyVar(tok);
      if (c.ok) continue;
      const bucket = c.exclusion ? 'unhonoredExclusions' : 'unsupportedVars';
      stats[bucket] = (stats[bucket] || 0) + 1;
      const listKey = bucket === 'unsupportedVars' ? 'unsupportedVarIds' : 'unhonoredExclusionIds';
      // 链上第 2+ 个节点没有自己的 id（CRS 把 id 只给链头），归因要退到链头，
      // 否则报告里出现 "?:TX:1" 这种查不到是谁的条目。
      const owner = rule.id || (curChain && curChain.id) || '(未知规则)';
      (stats[listKey] ||= new Set()).add(`${owner}:${tok}`);
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
  // 三个普查桶恒归一成**数组**：补全之后"没有缺口"必须是 `[]`，不能是"字段没建 ⇒ undefined"。
  // （selftest 断言 942 侧 `droppedTransforms` 为空，undefined 会让它红得莫名其妙——
  //   红的原因看起来像"断言写错了"，而真正该被看见的是"缺口没了"。）
  //
  // [2026-09-25] 词典两个桶也必须登记在这里，这不是格式统一洁癖而是补上的一个真 bug：
  //   没归一时它们是 Set，而消费侧按这套桶的既有写法判空 `if ((census.missingDicts || []).length)`
  //   —— Set 没有 `.length`，恒为 undefined ⇒ **缺失词典的告警永远不会响**。同一段代码里
  //   用 `[...]` 展开的那行却正常打印（Set 可迭代），于是报告说有缺口、控制台说没有，
  //   两边只有一边在撒谎，而撒谎的那边恰好是"看起来更安静"的那边。
  //   加新桶时若忘了这里，症状就是那道守卫静默空转。
  for (const k of ['unsupportedVarIds', 'unhonoredExclusionIds', 'droppedTransforms', 'missingDicts', 'emptyDicts']) {
    stats[k] = stats[k] instanceof Set ? [...stats[k]].sort() : [];
  }
  PARSE_STATS.set(confPath, stats);
  return rules;
}

// —— 变量取值：把请求对象映射为 CRS 变量名 → [值...] ——
// state 用于链式规则：captures = 上一节点正则的捕获组，matchedVals = 上一节点命中的值。
// CRS 的"条件式 SQLi"族（942130/942150/942521/942522…）靠 `TX:1`、`MATCHED_VARS` 表达
// "同一请求里还得有第二种信号"，不给这两个变量的值，那批规则就永远不匹配。

/**
 * 变量派发表的**唯一真相源**：`COLL[:selector]` 里的 COLL 部分。
 * kind 决定从请求的哪个面取值；`sel` 表示该形态支持元素选择器（`ARGS_GET:fbclid`）。
 *
 * 为什么要从 if 链改成表：原来是一条 if 链 + 末尾 `else push([])`，"哪种形态其实没人处理"
 * 在代码里根本看不出来 —— `ARGS_GET:fbclid` 就是这么静默恒空了两条排除规则（→ ctl 永不生效，
 * 表面症状却是"942440 误报"）。有了这张表，同一个判断既能驱动取值，又能被解析期普查复用，
 * "不支持"于是从**看不见的空值**变成**能数出来的缺口**。
 */
const VAR_KINDS = {
  ARGS: { kind: 'args', sel: true },
  ARGS_GET: { kind: 'args', sel: true },
  ARGS_POST: { kind: 'args', sel: true },
  ARGS_PATH: { kind: 'args', sel: true },
  ARGS_MULTIMATCH: { kind: 'args', sel: true },
  ARGS_NAMES: { kind: 'argsNames', sel: true },
  ARGS_GET_NAMES: { kind: 'argsNames', sel: true },
  ARGS_POST_NAMES: { kind: 'argsNames', sel: true },
  REQUEST_COOKIES: { kind: 'cookies', sel: false },
  REQUEST_COOKIES_NAMES: { kind: 'cookieNames', sel: false },
  REQUEST_HEADERS: { kind: 'headers', sel: true },
  REQUEST_URI: { kind: 'uri', sel: false },
  // ModSecurity 里 FILES = 上传文件的**文件名**（`filename="../x"` 的那个值），
  // FILES_NAMES = 表单里文件字段的**字段名**。930110/930120 靠 FILES 抓"上传文件名里带穿越"，
  // 此前本执行器连 FILES 都不认 ⇒ 该变量恒取不到值（普查点名过它）。FILES_SIZES 不建模。
  FILES: { kind: 'files', sel: false },
  FILES_NAMES: { kind: 'fileNames', sel: false },
  REQUEST_FILENAME: { kind: 'uri', sel: false },
  REQUEST_BASENAME: { kind: 'uri', sel: false },
  QUERY_STRING: { kind: 'queryString', sel: false },
  MATCHED_VARS: { kind: 'matchedVars', sel: false },
  MATCHED_VARS_NAMES: { kind: 'matchedVars', sel: false },
  // TX 的"选择器"是**数字下标**（`TX:1` = 链上前一节点的第 1 个捕获组），必须 sel:true，
  // 否则下面的数字校验根本轮不到 —— 实测：这里写成 false 会让 942521 等链式规则恒不命中，
  // 官方回归集当场冒出 23 条未点名分歧而 FAIL。
  TX: { kind: 'tx', sel: true },
};

/** 判断一个变量 token 的支持度。不支持的一律走这里点名，不再靠"落到 else 返回空"。 */
export function classifyVar(token) {
  const raw = String(token);
  const name = raw.replace(/^!/, '');
  const [coll, ...rest] = name.split(':');
  const sel = rest.join(':');
  const spec = VAR_KINDS[coll];
  // 两类"不支持"必须分开，它们的风险方向相反：
  //   · exclusion —— `!COLL:sel` 是要**从集合里扣掉**一部分。不扣只会让取值变多
  //     （偏保守：可能多命中，不会漏命中），所以它记一笔即可，不能和下面混成一个数。
  //   · gap —— 正向变量取不到值 ⇒ 该规则在这份数据上**恒不命中**，是真正的检测面缺口。
  const exclusion = raw.startsWith('!');
  const mk = (ok, extra) => ({ ok, exclusion, token: name, coll, ...extra });
  if (!spec) return mk(false, { why: exclusion ? '排除项未实现（未知集合无从扣起）' : '未知集合：该变量取不到值' });
  // 选择器**只在排除侧**先开放：`!REQUEST_COOKIES:/__utm/` 要按元素名扣就必须解析它；
  // 正向形态（`REQUEST_COOKIES:sid`）维持原状 —— 上一版把正向一起开放后回归集变红。
  if (sel && !spec.sel && !exclusion) return mk(false, { why: '该集合不支持选择器形态' });
  if (spec.kind === 'tx' && !/^\d+$/.test(sel || '')) return mk(false, { why: 'TX 仅支持数字下标（链捕获）' });
  return mk(true, { kind: spec.kind, sel: sel || null });
}

const push = (arr, vals) => { arr.push(...vals); };

export function collectValues(vars, req, state = {}, exclArgs = null) {
  const out = [];
  // ARGS 家族：有参数级豁免时按**名字**剔元素（ModSecurity 的 `ARGS:fbclid` 语义是
  // "ARGS 集合里叫 fbclid 的那个元素"，不是整族剔除）
  const argEntries = () => {
    const e = Object.entries(req.args || {});
    return exclArgs && exclArgs.size ? e.filter(([k]) => !exclArgs.has(k)) : e;
  };
  const pick = (entries, sel, wantNames) => {
    let list = entries;
    if (sel) {
      // 元素名 或 `/正则/` 两种选择器；本执行器的 req.args 是 query+body 合并视图，
      // 不区分来源子集（ARGS_GET/POST 落在一起，属**有意的近似**）。
      list = sel.startsWith('/') && sel.endsWith('/') && sel.length > 2
        ? list.filter(([k]) => new RegExp(sel.slice(1, -1), 'i').test(k))
        : list.filter(([k]) => k === sel);
    }
    return wantNames ? list.map(([k]) => k) : list.map(([, v]) => v);
  };
  // [2026-09-24 第二版，只走最小半径] `!COLL:sel` 扣除语义。上一版一次改了三件事
  // （按 (kind,元素名) 扣 / 正向也开放选择器 / 同集合去重），官方 805 例多出 12 条未点名分歧；
  // 关掉"扣"这步仍是同样多分歧 ⇒ 正向那两件才是元凶。本版**只做扣**，且：
  //   · 按**精确集合名**登记，不用 kind 归并 —— ModSecurity 里 REQUEST_COOKIES（值）与
  //     REQUEST_COOKIES_NAMES（名）是两个集合，扣一个不能连坐另一个；
  //   · 只扣有元素名的集合（ARGS / REQUEST_COOKIES / REQUEST_HEADERS）；
  //   · 正向取值一字不改。
  // 定点断言在 e2e/waf-real/selftest.mjs 的「变量列表语义」段：回归集对"值被扣但名不该被扣"
  // 这件事没有用例覆盖，只有那里拦得住（实测把 coll 折成 kind 会红 3 条）。
  const drops = new Map(); // 精确集合名 -> (元素名) => 是否扣掉
  for (const v of vars) {
    if (!v.startsWith('!')) continue;
    const c0 = classifyVar(v);
    if (!c0.ok || !c0.sel) continue;
    const m = c0.sel.startsWith('/') && c0.sel.endsWith('/') && c0.sel.length > 2
      ? ((re) => (k) => re.test(k))(new RegExp(c0.sel.slice(1, -1), 'i'))
      : ((sn) => (k) => k === sn)(c0.sel);
    drops.set(c0.coll, m);
  }
  const keptEntries = (coll, entries) => {
    const drop = drops.get(coll);
    return drop ? entries.filter(([k]) => !drop(k)) : entries;
  };
  for (const v of vars) {
    const neg = v.startsWith('!');
    // 取反变量（`!REQUEST_COOKIES:/__utm/`）在此**跳过**是有意为之：扣除已在循环前
    // 登记进 drops、取值时按精确集合名应用，这里不需要再往 out 里放任何东西。
    // 历史注脚：这行原来是"整条 no-op（等于一个都不扣）"，2026-09-24 起才有扣除语义；
    // 第一版实现把 (kind,元素名) 当扣除键、并顺手开放正向选择器与去重，被官方 805 例
    // 判出 12 条未点名分歧后回退重做（细节见上面 drops 段的注释）。
    if (neg) continue;
    const c = classifyVar(v);
    if (!c.ok) continue; // 不支持面由解析期普查点名，这里保持与旧实现一致的"返回空"
    switch (c.kind) {
      case 'args': push(out, pick(keptEntries(c.coll, argEntries()), c.sel, false)); break;
      case 'argsNames': push(out, pick(keptEntries(c.coll, argEntries()), c.sel, true)); break;
      case 'cookies': push(out, keptEntries(c.coll, Object.entries(req.cookies || {})).map(([, v2]) => v2)); break;
      case 'cookieNames': push(out, keptEntries(c.coll, Object.entries(req.cookies || {})).map(([k2]) => k2)); break;
      case 'headers':
        if (!c.sel) push(out, keptEntries(c.coll, Object.entries(req.headers || {})).map(([, v2]) => v2));
        else push(out, [req.headers[String(c.sel).toLowerCase()]].filter((x) => x != null));
        break;
      case 'uri': push(out, [req.uri]); break;
      case 'files': push(out, req.files || []); break;
      case 'fileNames': push(out, req.fileNames || []); break;
      case 'queryString': push(out, [req.queryString]); break;
      case 'matchedVars': push(out, state.matchedVals || []); break;
      case 'tx': {
        // 只有 `TX:<数字>`（链上节点的捕获组）有定义；TX:DETECTION_PARANOIA_LEVEL 之类
        // 由 classifyVar 判为不支持（本执行器不建模 PL 状态），与旧实现返回空等价。
        const g = state.captures;
        const n = Number(c.sel);
        push(out, g && g[n] != null ? [String(g[n])] : []);
        break;
      }
      default: break;
    }
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
  // @pmFromFile：词典里任一条目作为**不敏感子串**出现在取值里即命中（无词边界、无锚定，
  // 与 ModSecurity 的 Aho-Corasick 多模式匹配同语义）。
  // 返回**命中的那条词典条目**而非整段取值：CRS 用 %{TX.0} 在 logdata 里报告
  // "Matched Data"，那个位置语义上就是"词典里的哪条路径踩中了"。
  if (op.startsWith('@pmFromFile')) {
    if (!rule.dict) return null; // 词典没载入：由普查 missingDicts 报出来，不在此伪造命中
    const hay = String(value).toLowerCase();
    for (const item of rule.dict) if (hay.includes(item)) return negated ? null : [item];
    return negated ? [value] : null;
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
  // ctl:ruleRemoveTargetById 的落地状态：规则 id -> 被豁免的参数名集合。
  // 语义按 ModSecurity：**从本条排除规则命中之后**才对后续规则生效（按文件顺序求值，
  // 而 CRS 把排除规则放在被豁免规则之前），所以这里只需前向累积、不需要回退。
  const exclByRule = new Map();
  for (const group of evaluate._rules) {
    const nodes = group.chain || [group];
    // PL 截断（规则所在区块 PL > 配置上限 → 跳过）
    if (nodes.some((n) => n.pl > maxPL)) continue;
    const exclArgs = exclByRule.get(group.id) || null;
    let allHit = true;
    // [CHAIN-FIX] 链式规则按 ModSecurity 语义逐节点求值，并把上一节点的**捕获组**与**命中的值**
    // 传给下一节点（`TX:1` / `MATCHED_VARS` / `&…@ge N` 全靠这两个状态）。
    let state = {};
    for (const node of nodes) {
      const values = collectValues(node.vars, req, state, exclArgs).map((v) => applyTransforms(v, node.transforms));
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
      // 命中才施加 ctl（ModSecurity 里 ctl 是动作，规则没命中就不该改别人的取值面）
      for (const n of nodes) {
        for (const r of n.ctlRemove || []) {
          if (!exclByRule.has(r.ruleId)) exclByRule.set(r.ruleId, new Set());
          exclByRule.get(r.ruleId).add(r.name);
        }
      }
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

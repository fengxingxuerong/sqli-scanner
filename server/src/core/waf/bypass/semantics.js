// ============================================================================
// semantics.js —— tamper 插件的「语义索引」与定向选弹能力
// [P0-A1 2026-09-22]
//
// ■ 为什么不是「再建一个变换库」（方向纠偏，有据）
//   `docs/全方面优化方案-渗透实战视角-2026-09-21.md` §A1 原计划新建语义等价变换库，
//   其表格列举的每一类等价变换，核实后**在 core/tamper/plugins/（228 个）中均已存在**：
//     逻辑算符 symboliclogical · 比较算符 equaltolike/equaltorlike/noequals ·
//     空白 space2*（60+）· 函数等价 substring2mid/commalessmid · 字符串构造
//     hexliterals/quote2hex/apostrophe2char · 数字 scientific · 结构 misunion/0eunion/
//     unionalltounion/union2no · 版本注释 versionedkeywords/modsecurity* · 比较 between
//   再写一份即重复造轮子，且会立刻与既有链守卫（幂等 / terminal / dbms 过滤）脱节。
//   → 本模块**不复制任何变换逻辑**，变换实现一律留在 plugins/。
//
// ■ 真实缺口 = 元数据维度（这才是「有弹药没枪法」的成因）
//   既有插件只有人类可读的 `description`，没有机器可用的
//   「消除哪些 token / 引入哪些 token / 付出多少标点代价」。
//   危害有实测证据：core/waf/wafRecommend.js 注释记录了 symboliclogical 在 CRS 下是
//   **负收益**（REQUEST-942-SQLI.conf 的 942120 正则里直接写着 && / ||），
//   只能用于关键词级黑名单；equaltorlike 叠加也会掉命中。
//   —— 即「一条变换的收益方向无法从名字推断」，必须量化才能定向选弹。
//
// ■ 本模块交付（供 bypass/searcher.js 消费）
//   ① 语义索引：类别 / eliminates / mutates / introduces / reducesPunct / 实测方向
//   ② 定向选弹：selectByAvoiding(黑名单词表) → 候选插件名
//   ③ 代价度量：最长非词字符连续串（对齐 CRS 942460「4 连非词字符」真实判据）
//
// ■ 三个 token 维度的区别（不要把三者混为一谈，各有独立的机械判据）
//   · `eliminates`：输出中该 token **字面消失**（如 symboliclogical 消掉 `or`）。
//       ⟶ 判据：样本含该 token，transform 后不再匹配。
//   · `mutates`：该 token 字面**仍在**，但形态被打散（如 unions 的 UNI/**/ON、
//     版本注释 /*!SELECT*/）。对"简单正则删除型"WAF 仍会命中词本身 ⟶ 选弹时**必须排除**。
//       ⟶ 判据：只在 selectByAvoiding 里用作排除依据，不做"消失"断言（会假红）。
//   · `reducesPunct`：不消除任何 token，但**降低最长非词字符连续串**（dash2hash：
//     `-- -` 4 连 → `#` 1 连）。这是 CRS 942460/942431 的正面对抗维度，
//     也是 wafRecommend.js 记录的"减标点方向唯一有效项"。
//       ⟶ 判据：maxNonWordRun(out) < maxNonWordRun(in)。
//   ⚠️ 首版曾把 dash2hash 误标为 eliminates:['--']，被机械检验当场打回（`1-- -` → `1-- `）。
//   · `eliminatesAll`：整串被编码/转义 ⇒ **全部明文关键词一起消失**（不是消除某一个 token）。
//     编码族（`*encode` / `charunicode*` / `hexentities`）属此类。
//     ⚠️ 它是**兜底弹药**：目标必须做对应预解码才有效，故选弹时应排在"针对性消除"之后。
//
// ■ 口径边界（诚实标注）
//   - `eliminates` 只声明**可机械验证**的结论（输出中该 token 字面消失），
//     由 waf.bypassSemantics.test.js 用插件自身 transform 实测守卫，不靠人工声明取信。
//   - 非词字符判定沿用 ASCII 定义 `[^A-Za-z0-9_]`；CRS 用 PCRE，两者在 `\s` 扩字符集上
//     存在已知差异（本项目实测：JS 的 \s 比 PCRE 宽），故此处的代价度量是
//     **相对指标**（同一目标下比较两套链的优劣），不是对 CRS 分值的精确复算。
// ============================================================================

import { tamperRegistry } from '../../tamper/TamperRegistry.js';
import '../../tamper/applyTampers.js'; // 副作用：注册内置插件
import { logger } from '../../logger.js';

/** 变换的语义类别 */
export const SEMANTIC_CATEGORIES = {
  /** 语法等价：算子/函数/子句的等价改写（语义不变，形态变） */
  SYNTACTIC: 'syntactic',
  /** 词法拆分：关键词被注释/双写/版本注释打散，字面仍在但无法整词匹配 */
  LEXICAL: 'lexical',
  /** 空白替换：空格换成其它空白或注释 */
  WHITESPACE: 'whitespace',
  /** 字面量编码：字符串/数字换成 hex/CHAR()/科学计数等等价构造 */
  LITERAL: 'literal',
  /** 传输编码：URL/Unicode 等编码层变换 */
  ENCODING: 'encoding',
};

/**
 * 实测收益方向（有证据才写，无证据留空 —— 不编因果）
 * @readonly
 */
export const EVIDENCE = {
  /** CRS PL1 下负收益：942120 正则直接含该符号，见 wafRecommend.js 注释 */
  CRS_NEGATIVE: 'crs-negative',
  /** CRS 下正收益：减少非词字符连续串（942460/942431 标点预算） */
  CRS_PUNCT_GAIN: 'crs-punct-gain',
  /** 仅对关键词级黑名单（strip 型）有效 */
  KEYWORD_BLACKLIST_ONLY: 'keyword-blacklist-only',
};

/**
 * 手工精标：语义明确、选取价值高的插件。
 * 只写**能被测试机械验证**的字段：`eliminates`（输出中该 token 消失）、
 * `introduces`（新出现的 token）。`note` 为人读依据，不参与判定。
 * @type {Record<string, {category:string, eliminates?:string[], introduces?:string[], mutates?:string[], reducesPunct?:boolean, eliminatesAll?:boolean, applicablePattern?:string, evidence?:string, note?:string}>}
 */
export const CORE_SEMANTICS = {
  symboliclogical: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['and', 'or'],
    introduces: ['&&', '||'],
    evidence: EVIDENCE.CRS_NEGATIVE,
    note: 'CRS 942120 正则直接含 && / || → PL1 下负收益；仅关键词级黑名单（strip 型）有效',
  },
  equaltolike: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['='],
    introduces: [' like '],
    note: '复合运算符 <=/>=/!=/<> 受锚点保护不改写',
  },
  equaltorlike: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['='],
    introduces: [' rlike '],
    evidence: EVIDENCE.KEYWORD_BLACKLIST_ONLY,
    note: 'wafRecommend.js 实测：叠加到 dash2hash 链上会掉命中（部分 DBMS/上下文语义不等价）',
  },
  noequals: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['='],
    introduces: [' like '],
    note: '带引号保护，与 equaltolike 的差异在字符串字面量内不改写',
  },
  between: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['>'],
    introduces: [' not between '],
    note: '只改裸 >，跳过 >=/<=/<>，不改写 <（对齐 sqlmap）',
  },
  scientific: {
    category: SEMANTIC_CATEGORIES.LITERAL,
    eliminates: [],
    introduces: ['e'],
    note: '数字 → 科学计数法，等价但改变字面量形态',
  },
  hexliterals: {
    category: SEMANTIC_CATEGORIES.LITERAL,
    eliminates: ["'"],
    introduces: ['0x'],
    evidence: EVIDENCE.CRS_PUNCT_GAIN,
    note: 'wafRecommend 实测：与 dash2hash 组成首选链 —— 消除引号锚点后 CRS 942300 不再命中',
  },
  quote2hex: {
    category: SEMANTIC_CATEGORIES.LITERAL,
    eliminates: ["'"],
    introduces: ['0x'],
  },
  apostrophe2char: {
    category: SEMANTIC_CATEGORIES.LITERAL,
    eliminates: ["'"],
    introduces: ['char('],
  },
  decimal2char: {
    category: SEMANTIC_CATEGORIES.LITERAL,
    eliminates: ["'"],
    introduces: ['char('],
  },
  substring2mid: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['substring'],
    introduces: ['mid'],
  },
  substring2left: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['substring'],
    introduces: ['left', 'right'],
  },
  substring2leftright: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['substring'],
    introduces: ['left', 'right'],
    // ⚠️ 实际匹配面极窄：源码只认 PostgreSQL 的 `SUBSTRING(A FROM B FOR 1)` 拼写
    // （见 plugins/substring2leftright.js 的 match 正则）。
    // **最常见的逗号形态 SUBSTRING(a,1,1) 直接空转** —— 选弹前必须确认 payload 形态，
    // 否则"选中了却白跑"。此边界由 waf.bypassSemantics.test.js 的专属样本钉住。
    applicablePattern: 'SUBSTRING\\(A FROM B FOR 1\\)（仅 PostgreSQL 拼写）',
    note: '逗号形态 SUBSTRING(a,1,1) 空转，勿在非 PG 场景选它',
  },
  concat2concatws: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['concat('],
    introduces: ['concat_ws('],
  },
  concat2ws: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['concat('],
    introduces: ['concat_ws('],
  },
  nconcatenation: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    eliminates: ['concat('],
    introduces: [],
  },
  keywordinterleave: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['and', 'or', 'union', 'select'],
    note: '插入式双写（AND→ANANDD）：字面仍在，靠「删一次后还原」生效，故走 mutates 而非 eliminates',
  },
  keywordSplit: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or'],
    note: '关键字内部插 /*!*/，破坏整词匹配；字面仍在',
  },
  versionedkeywords: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or', 'from', 'where'],
    evidence: EVIDENCE.KEYWORD_BLACKLIST_ONLY,
    note: '用 /*!KEYWORD*/ 包裹，仅 MySQL 解析内联',
  },
  versionedmorekeywords: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or', 'from', 'where'],
  },
  halfversionedmorekeywords: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or'],
    note: '/*!50540 KEYWORD*/，MySQL 5.5.40+ 执行',
  },
  modsecurityversioned: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or'],
  },
  misunion: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['union'],
    note: 'UNION→UNI/**/ON，破坏整词匹配',
  },
  union2no: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['union'],
  },
  '0eunion': {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['union'],
  },
  dunion: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['union'],
  },
  unionalltounion: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    mutates: ['all'],
    note: 'UNION ALL→UNION：去重语义不同，行数可能变化（注入场景通常无碍，但要知情）',
  },
  randomunion: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['union', 'select'],
  },
  comments: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'and', 'or'],
    introduces: ['/*! */'],
  },
  randomcomments: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['select', 'union', 'where', 'and', 'or', 'from', 'order', 'by'],
    introduces: ['/**/'],
  },
  informationschemacomment: {
    category: SEMANTIC_CATEGORIES.LEXICAL,
    mutates: ['information_schema'],
    introduces: ['/**/'],
  },
  multiplespaces: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    mutates: [],
    note: '关键字后追加额外空格，破「关键字紧邻」类规则',
  },
  dash2hash: {
    category: SEMANTIC_CATEGORIES.SYNTACTIC,
    // ⚠️ 它**不消除** `--`，而是把「4 连非词字符」规整为「3 连」：
    //   MySQL 系 → `#`（1 个非词字符）；其余方言 → `-- `（3 连，SQL92 标准行注释）。
    //   首版此处误写 eliminates:['--']，被 waf.bypassSemantics.test.js 的机械检验当场打回
    //   （实测 `1-- -` → `1-- `，`--` 仍在）—— 这正是"不采信声明"的价值。
    //   它的真实价值属于**另一个维度**：降低标点代价（对齐 CRS 942460/942431）。
    reducesPunct: true,
    evidence: EVIDENCE.CRS_PUNCT_GAIN,
    note: 'wafRecommend 实测：`-- -` 是 4 连非词字符（942460）→ 换 `#` 是减标点方向唯一有效项，CRS 下 tamper on 2/5→5/5',
  },
  space2span: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    // ⚠️ 同为族规则反例：`/^space2/` 统一声明 eliminates:[' ']，但 space2span 的替换文本
    //   `<span> </span>` **本身含空格** → 裸空格虽被包装，空格字符并未消失（WAF 的 \s 仍能命中）。
    //   故按 mutates 建模。族规则无法覆盖这类反例，必须精标（族的 eliminates 由测试逐条实测把关）。
    mutates: [' '],
    introduces: ['<span>'],
    note: '替换文本含空格：非 elimination，仅包装形态变化',
  },
  // ── 白名单首档：只消除标点、不改语义（标点预算方向的默认弹药） ──
  space2comment: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    eliminates: [' '],
    introduces: ['/**/'],
    note: '引号状态机保护字符串字面量内的空格',
  },
  space2hash: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    eliminates: [' '],
    introduces: ['#'],
  },
  space2mysqlblank: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    eliminates: [' '],
    introduces: ['\t'],
  },
  space2mssqlblank: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    eliminates: [' '],
    introduces: ['\t'],
  },
  space2randomblank: {
    category: SEMANTIC_CATEGORIES.WHITESPACE,
    eliminates: [' '],
    introduces: ['\t'],
  },

  // ── 整串编码族（eliminatesAll）：**逐条实测精标**，不靠族规则按名字推 ──
  // 判据（waf.bypassSemantics/Searcher 测试机械守卫）：应用到含 AND/UNION 的样本后，
  // 明文关键词必须消失。族内 14 个插件里只有下面 6 个成立（其余 8 个只动特殊字符）。
  charencode: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '整串 URL 编码（实测明文消失）；TERMINAL —— 其后插件失效',
  },
  chardoubleencode: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '双重 URL 编码；TERMINAL',
  },
  charunicodeencode: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '字母 → %uXXXX（实测明文消失）',
  },
  charunicodeescape: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '字符 → \\uXXXX（实测明文消失）',
  },
  base64encode: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '整串 base64（实测明文消失）',
  },
  hexentities: {
    category: SEMANTIC_CATEGORIES.ENCODING,
    eliminatesAll: true,
    note: '字符 → &#xHH 十六进制实体（实测明文消失；注意与 htmlencode 的区别 —— 后者只编特殊字符）',
  },
};

/**
 * 同构族规则：按插件名前缀/后缀批量派生元数据（避免 60+ 个 space2* 逐条手抄）。
 * 规则只做**形态归类**，不猜收益方向（收益方向一律留空，有实测才手写进 CORE_SEMANTICS）。
 * @type {Array<{test:RegExp, tie:{category:string, eliminates?:string[], introduces?:string[], mutates?:string[], eliminatesAll?:boolean, note?:string}}>}
 */
export const FAMILY_RULES = [
  // space2<X>：空格 → X 形态（60+ 个）
  { test: /^space2/, tie: { category: SEMANTIC_CATEGORIES.WHITESPACE, eliminates: [' '], note: 'space2* 族：空格替换（引号保护）' } },
  // tab2/newline2/comment2：空白与注释互换
  { test: /^tab2/, tie: { category: SEMANTIC_CATEGORIES.WHITESPACE, eliminates: ['\t'] } },
  { test: /^newline2/, tie: { category: SEMANTIC_CATEGORIES.WHITESPACE, eliminates: ['\n'] } },
  { test: /^comment2/, tie: { category: SEMANTIC_CATEGORIES.WHITESPACE, eliminates: ['/**/'] } },
  // char*encode / *escape：传输编码族
  // ⚠️ **本族绝不按名字声明 `eliminatesAll`** —— 已实测踩坑：`/encode$/` 看似"整串编码"，
  //   但族内 14 个插件里只有 6 个真的让明文关键词消失，其余 8 个只动特殊字符：
  //     明文消失 ✅ charencode / chardoubleencode / charunicodeencode / charunicodeescape
  //                / base64encode / hexentities
  //     明文仍在 ❌ htmlencode(`1&#32;AND&#32;1&#61;1`) / dbase64encode / octalencode
  //                / doubleencode / floatencode / unhtmlencode / apostrophenullencode（后者空转）
  //   → `eliminatesAll` 一律在 CORE_SEMANTICS 里**逐条精标**，并由测试用真实 transform 兑现。
  {
    test: /encode$|^charunicode|^hexentities/,
    tie: {
      category: SEMANTIC_CATEGORIES.ENCODING,
      note: '编码/转义族：是否消除明文取决于实现，不可从名字推断（见 CORE_SEMANTICS 的逐条精标）',
    },
  },
  // keyword2<X>：关键词变形
  { test: /^keyword2/, tie: { category: SEMANTIC_CATEGORIES.LEXICAL, mutates: [], note: 'keyword2* 族：关键字形态变形' } },
  // 进制互转：hex2/char2/bin2/dec2/num2/oct2
  { test: /^(hex2|char2|bin2|dec2|num2|oct2|str2|string2|randomascii)/, tie: { category: SEMANTIC_CATEGORIES.LITERAL } },
];

/** @type {Map<string, object>|null} 构建后的完整索引（懒加载） */
let _index = null;

/**
 * 构建语义索引：手工精标优先，未命中者按同构族规则派生。
 * 未识别的插件显式标 `category: 'unclassified'` —— 不假装覆盖（诚实边界）。
 * @returns {Map<string, object>}
 */
export function buildSemanticIndex() {
  if (_index) return _index;
  const idx = new Map();
  for (const p of tamperRegistry.all()) {
    const core = CORE_SEMANTICS[p.name];
    if (core) {
      idx.set(p.name, { name: p.name, source: 'curated', ...core });
      continue;
    }
    const rule = FAMILY_RULES.find((r) => r.test.test(p.name));
    idx.set(p.name, rule
      ? { name: p.name, source: 'family', ...rule.tie }
      : { name: p.name, source: 'unclassified', category: 'unclassified' });
  }
  _index = idx;
  return idx;
}

/**
 * 列举带语义元数据的插件
 * @param {{category?:string, onlyCurated?:boolean}} [filter]
 * @returns {Array<object>}
 */
export function listSemantics(filter = {}) {
  const idx = buildSemanticIndex();
  let out = [...idx.values()];
  if (filter.category) out = out.filter((e) => e.category === filter.category);
  if (filter.onlyCurated) out = out.filter((e) => e.source === 'curated');
  return out;
}

/**
 * 索引覆盖度（诚实报告，供测试与报告引用）
 * @returns {{total:number, curated:number, family:number, unclassified:number, unclassifiedNames:string[]}}
 */
export function indexCoverage() {
  const all = [...buildSemanticIndex().values()];
  const unclassifiedNames = all.filter((e) => e.source === 'unclassified').map((e) => e.name).sort();
  return {
    total: all.length,
    curated: all.filter((e) => e.source === 'curated').length,
    family: all.filter((e) => e.source === 'family').length,
    unclassified: unclassifiedNames.length,
    unclassifiedNames,
  };
}

/**
 * 最长非词字符连续串长度 —— 对齐 CRS 942460「4 连非词字符」/942431「6 特殊字符」的
 * 真实判据形态。**相对指标**：同一目标下比较两套链的优劣，非 CRS 分值的精确复算。
 * @param {string} s
 * @returns {number}
 */
export function maxNonWordRun(s) {
  let max = 0;
  let cur = 0;
  for (const ch of String(s)) {
    if (/[^A-Za-z0-9_]/.test(ch)) {
      cur += 1;
      if (cur > max) max = cur;
    } else {
      cur = 0;
    }
  }
  return max;
}

/**
 * 选弹（T2 搜索器的核心入口）：给定目标的**黑名单词表**，
 * 挑出「不引入也不保留这些词」的插件名。
 *
 * 判定规则：
 *  - 插件的 `mutates` 命中黑名单 → 排除（该词字面仍在，简单正则仍会匹配）；
 *  - 插件的 `introduces` 命中黑名单 → 排除（换了个词又被拦，等于没换）；
 *  - `eliminates` 命中黑名单 → **加分**（正面对抗目标黑名单）；
 *  - `unclassified` 且目标黑名单非空 → 排除（不认识的不敢用，避免盲试噪声）。
 *
 * @param {string[]} blocked 目标黑名单词表（小写；来自 A2 的拦截画像）
 * @param {{dbms?:string}} [ctx] 保留参数：dbms 适用性属**链级**判据，请在组装成链后
 *   交给 `TamperRegistry.validateChain(chain, { dbms })`；本函数不做链级判定（见下方注）
 * @returns {{usable:string[], dropped:Array<{name:string, reason:string}>, boosted:string[]}}
 */
export function selectByAvoiding(blocked = [], ctx = {}) {
  const words = (blocked || []).map((w) => String(w).toLowerCase()).filter(Boolean);
  const idx = buildSemanticIndex();
  const usable = [];
  const dropped = [];
  const boosted = [];

  for (const p of tamperRegistry.all()) {
    const meta = idx.get(p.name);
    // dbms 不匹配者交由既有 registry 守卫告警（不在本模块重复实现该判据）
    if (meta.category === 'unclassified' && words.length > 0) {
      dropped.push({ name: p.name, reason: 'unclassified' });
      continue;
    }
    const hitMutates = (meta.mutates || []).find((m) => words.includes(String(m).toLowerCase()));
    if (hitMutates) {
      dropped.push({ name: p.name, reason: `mutates:${hitMutates}` });
      continue;
    }
    const hitIntroduces = (meta.introduces || []).find((m) => {
      const t = String(m).toLowerCase().replace(/[^a-z0-9_]/g, '');
      return t && words.includes(t);
    });
    if (hitIntroduces) {
      dropped.push({ name: p.name, reason: `introduces:${hitIntroduces}` });
      continue;
    }
    usable.push(p.name);
    const hitEliminates = (meta.eliminates || []).find((m) => words.includes(String(m).toLowerCase()));
    if (hitEliminates) boosted.push(p.name);
  }

  // ⚠️ 此处**不得**调用 `tamperRegistry.validateChain(usable, ctx)` —— 已实测踩坑：
  //    那是**链级**判据（含 `terminal` 截断语义）。把 228 个插件的**清单**当一条链传进去，
  //    第一个 terminal 插件（如 charencode）之后的所有插件会被**静默截断丢弃**。
  //    症状：拦 `and`/`or` 时候选池只剩编码兜底，`symboliclogical`（eliminates: and,or）
  //    因为排在 charencode 之后而被整个丢掉 —— 选弹功能形同虚设。
  //    ✅ 逐**链**校验的正确位置在 bypass/searcher.js 的 push()（那条路径上输入本来就是链）。
  //    dbms 适用性同理属链级上下文，故本函数只做"单插件层面"的可用性筛选。
  return { usable, dropped, boosted };
}

/**
 * 估算一套链的「标点代价」（相对指标）。
 * @param {string[]} names 插件名链
 * @param {string} sample 样本 payload（建议用待变换的真实 payload）
 * @returns {{before:number, after:number, delta:number, failed:string[]}}
 */
export function estimatePunctCost(names = [], sample = "'1' UNION SELECT 1-- -") {
  const before = maxNonWordRun(sample);
  let out = String(sample);
  const failed = [];
  for (const p of tamperRegistry.resolve(names)) {
    try {
      out = p.transform(out, {});
    } catch (e) {
      failed.push(p.name);
    }
  }
  const after = maxNonWordRun(out);
  return { before, after, delta: after - before, failed };
}

/**
 * 启动期完整性断言（fail-fast，对齐 assertTamperNames 的既有做法）：
 * 索引里出现的插件名必须真实注册；`eliminates` 声明必须非空数组，防"标了等于没标"。
 * 索引腐烂（写了仓库里不存在的插件名）会当场报错，而不是静默失效。
 * @throws {Error}
 */
export function assertIndexIntegrity() {
  const problems = [];
  for (const name of Object.keys(CORE_SEMANTICS)) {
    if (!tamperRegistry.get(name)) problems.push(`CORE_SEMANTICS 里的插件不存在：${name}`);
  }
  for (const [name, meta] of buildSemanticIndex()) {
    if (meta.source === 'curated') {
      const hasPayload = (meta.eliminates?.length || 0) + (meta.mutates?.length || 0) +
        (meta.introduces?.length || 0) + (meta.reducesPunct ? 1 : 0) + (meta.eliminatesAll ? 1 : 0);
      // 允许「纯说明型」条目（只写 note），但必须至少写 note，否则是空壳
      if (!hasPayload && !meta.note) problems.push(`CORE_SEMANTICS.${name} 既无 token 声明也无 note（空壳条目）`);
    }
  }
  if (problems.length) throw new Error(`语义索引完整性校验失败：\n  - ${problems.join('\n  - ')}`);
  return true;
}

// 模块加载即自检（与 wafRecommend.js 的 assertRecommendNames 同风格）
assertIndexIntegrity();

if (process.env.WAF_BYPASS_SEMANTICS_VERBOSE === '1') {
  const c = indexCoverage();
  logger.info(`语义索引就绪：总 ${c.total} / 精标 ${c.curated} / 族派生 ${c.family} / 未分类 ${c.unclassified}`);
}

export default { buildSemanticIndex, selectByAvoiding, listSemantics, indexCoverage };

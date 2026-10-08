import { assertRecommendNames } from './assertTamperNames.js';
import { WAF_RECOMMEND_MAP } from './wafRecommendMap.js';
// 再导出：既有 import 路径保持不变
export { WAF_RECOMMEND_MAP } from './wafRecommendMap.js';

/**
 * 关键词级过滤场景的候选链（拦截驱动重跑用，按命中率从高到低）。
 * 说明：symboliclogical 单独一条最优——叠加 equaltorlike 会把 `1=1` 改成 `1 RLIKE 1`，
 * 在部分 DBMS/上下文语义不等价，实测同靶场反而掉了命中（见 waf-diag）。
 */
export const OPERATOR_SWAP_CHAINS = [
  // [P0-FIX 2026-09-10] 顺序按「通用收益」重排，dash2hash 提到第一位：
  // CRS 系规则真正卡人的不是关键词，而是 942460（4 连非词字符）/942431（6 特殊字符）的
  // 「标点预算」——`-- -` 正是 4 连非词字符。dash2hash 把尾注换成 `#`（1 个字符），
  // 是「减少标点」方向唯一有效项，实测把 CRS 下 tamper on 从 2/5 拉到 5/5、技术位 10。
  // 而 symboliclogical 在 CRS 下是**负收益**（942120 正则里直接写着 && / ||），
  // 只能用于关键词级黑名单（自研/云 WAF 的 strip 规则）。
  // chainVerify 的 MAX_CHAINS=3，故只保留收益最高的三条。
  // [P0-FIX 2026-09-10 实测] `dash2hash` 单独用时会把 `'标记'#` 形态留在 payload 里，而
  // CRS 942300 的正则含 `["'`]\s*?(?:[#\{]|--)` —— **引号后紧跟 `#` 即拦**。
  // union 的标记回显探测（`1 UNION SELECT 'SQLISCANNER0'#`）正好命中该形态，实测 403 942300，
  // 导致数值型场景（num/blind）union 面缺失。叠加 `hexliterals`（`'abc'` → `0x616263`，
  // 两插件均已声明 markerSafe）后标记无引号锚点 → 942300 不命中。故把该组合提为首选链。
  // [批次 D4 2026-10-05 真机链对拍（modsec-live #162）→ 已实测后回退，证据保留在
  //   docs/WAF-真机链对拍-2026-10-05.md]
  //   真机数据：dash2hash×hexliterals（本链）在真 CRS PL1 下 0 打穿 0 放行；
  //   unionvaluesrow+dash2hash 2/19 打穿——曾据此把 unionvaluesrow 系提为首选，
  //   但 artifact-drift 门禁当场抓到回归：multi-engine PL1 lab 的 tamper 腿在
  //   H2/HSQLDB 上 **union 技术丢失**（VALUES ROW 是 MySQL 8 语法，JDBC 引擎不认）。
  //   ⇒ 通用链表必须服务所有 DBMS，MySQL 专用的 unionvaluesrow 不能进通用首选。
  //   待办：DBMS 感知的链选择（确认目标方言后再选 unionvaluesrow 系）。
  ['dash2hash', 'hexliterals'],
  ['dash2hash'],
  ['symboliclogical'],
  // ↑ 前三条进 chainVerify 的 MAX_CHAINS=3。
  //   链1=CRS 内容规则（减标点 + 去引号锚点）；链2=通用减标点；
  //   链3=关键词级黑名单（自研/云 WAF 的 strip 规则，symboliclogical 换算子才有效）。
  ['hexliterals', 'dash2hash'],
  // [D4 真机] unionvaluesrow 系（2/19 打穿）仅限**确认 MySQL 8+ 目标**时手动指定，
  // 或等 DBMS 感知链选择落地后再自动化：
  // ['unionvaluesrow', 'dash2hash'] —— 真机打穿证据见 docs/WAF-真机链对拍-2026-10-05.md
];

// [D19 2026-10-09] 「编码兜底」静态候选 —— 为什么必须有它、且必须在这一层显式给出：
//
// 背景：`e2e/pentest-lab` 的 `waf403`（关键字即拦；靶场是 `if (WAF_RE.test(解码一次后的值)) 403`）
// 期望引擎换 boolean 通道重跑，前提是**候选链里至少有一条能过该 WAF**。
// 实测归因（`acceptance` 连续 3 个 run 红 → D18/D19）：那条链一直是 `chardoubleencode`
// （**双重 URL 编码**：WAF 只解一次码 ⇒ 它仍是编码态；单编码如 `encode2hex` 解码后是明文 ⇒ 必拦），
// 而它此前只靠 `planChainsByProfile` 的**动态生成**进候选 —— D15 放行 41 件未分类弹药后，
// 编码族里一批冷门项按 `scoreMeta` 的 covers/punct 打分排到它前面，它掉到 codec 序列第 30+，
// 而 chainVerify 的兜底名额只取 `codecs[0]` ⇒ **被静默挤出**。
//
// ⇒ 它**有真机证据**（D14 复验 head `50237e5` 时 acceptance 全绿，靠的正是它），
//   却没有任何显式位置 ⇒ 登记进静态候选表（与 unionvaluesrow 系同等对待：有证据就登记，不靠排序争）。
// ⚠️ 与 OPERATOR_SWAP_CHAINS 分开放：那不是"算子替换"而是"传输层编码"，语义不同。
//   通用性：纯 URL 编码、不依赖 DBMS，对所有引擎/靶场都安全。
export const ENCODING_FALLBACK_CHAINS = [
  ['chardoubleencode'],
];

/**
 * 编码兜底链在候选里的 **vendor 标记**（[D20 2026-10-09]）。
 *
 * 为什么需要一个专门的标记值：`chainVerify.pickChainsToVerify` 的名额分配需要**认出**兜底链
 * 才能给它保底（"兜底能力必须显式留名额，不能靠排序争" —— 与 OPERATOR/GENERATED 同源纪律）。
 *
 * ⚠️ 此前 D18 想靠 `chain.isCodec` 识别，但那个字段**只由 `planChainsByProfile` 动态生成的链携带**，
 * 静态链（来自本表）没有它 ⇒ 保底分支恒不触发（D18 因此无效，见 CHANGELOG）。
 * 现在改为**显式 vendor 标记**，静态链也认得出来。
 * 注意：它不以 `bypass:` 开头 ⇒ `isGeneratedChain` 仍判它**不是**生成链（不占生成名额）。
 */
export const ENCODING_FALLBACK_VENDOR = 'encoding_fallback';

/**
 * 关键词「静默过滤」场景的候选链（删除型规则：不返 403，只把 union/select/and/-- 删掉）。
 * 顺序依据实测（e2e/pentest-lab/bl）：插入式双写 + 注释符换 `#` 一条即可命中布尔面；
 * 单用 `keywordinterleave` 会因 `--` 被删而语法错误，故 dash2hash 必须同链。
 */
// [批次 D5 2026-10-05] MySQL 目标专属链（真机打穿形态，modsec-live #162 链对拍：
//   unionvaluesrow+dash2hash 真机 2/19 打穿，而通用首选链 dash2hash×hexliterals 真机
//   0 打穿 0 放行——见 docs/WAF-真机链对拍-2026-10-05.md）。
//   ⚠️ 仅当 DBMS 指纹确认 MySQL 时由 detect.js 前置进候选（VALUES ROW 是 MySQL 8.0.19+
//   语法，MariaDB 明确拒绝、H2/HSQLDB/Derby 不认——multi-engine lab 回归实证）。
//   通用链表 OPERATOR_SWAP_CHAINS 保持 DBMS 无关。
export const MYSQL_DBMS_CHAINS = [
  ['unionvaluesrow', 'dash2hash'],
  ['unionvaluesrow', 'dash2hash', 'hexliterals'],
];

export const FILTER_BYPASS_CHAINS = [
  ['keywordinterleave', 'dash2hash'],
  ['keywordinterleave'],
  ['dash2hash', 'keywordinterleave'],
];

/**
 * 依据识别到的 WAF 候选，给出推荐 tamper 组合（仅推荐，不自动套用）。
 * @param {Array<{vendor:string, confidence:number, evidence:string}>} vendors WafIdentifier.identify 结果
 * @returns {Array<{vendor:string, plugins:string[]}>} 仅保留命中映射且 plugins 非空的项
 */
export function recommend(vendors) {
  const arr = Array.isArray(vendors) ? vendors : [];
  return arr
    .map((v) => ({ vendor: v.vendor, plugins: WAF_RECOMMEND_MAP[v.vendor] || WAF_RECOMMEND_MAP._default || [] }))
    .filter((s) => s.plugins.length > 0);
}

// 遍历映射表时排除 _default（它不是真实 vendor，只是 fallback 预设）
export const WAF_VENDORS = Object.keys(WAF_RECOMMEND_MAP).filter((k) => k !== '_default');

export default recommend;

// —— WAF-v2 启动期静态断言（fail-fast）：服务启动/测试加载即校验推荐名全部 ∈ tamperRegistry，
// 防止误写未注册名（recommend() 函数体不变，铁律）。
assertRecommendNames();

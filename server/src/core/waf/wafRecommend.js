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
  // [批次 D4 2026-10-05 真机链对拍（modsec-live #162，modsec-docker-pl1-2026-10-05.md）]
  // 真机数据推翻了旧的隐含排序：dash2hash×hexliterals（旧首选）在真 CRS PL1 下
  // **0/19 打穿、0/19 放行**——本地自实现口径（PL1 放行、tamper on 5/5）与真机天花板
  // 出现了实测背离；而 unionvaluesrow 系链真机 2/19 打穿、3/19 放行，是唯一真机有效的形态。
  // 故真机打穿链提为第一顺位；旧的减标点链保留在第二/三顺位（自实现口径下仍有效，
  // 且 union 的标记回显探测依赖 hexliterals 的引号锚点消除——见下条实测注释）。
  ['unionvaluesrow', 'dash2hash'],
  ['dash2hash', 'hexliterals'],
  ['dash2hash'],
  // ↑ 前三条进 chainVerify 的 MAX_CHAINS=3。
  //   链1=真机实证打穿链（MySQL 表值构造器消 SELECT + 减标点）；
  //   链2=CRS 内容规则（减标点 + 去引号锚点，自实现口径首选）；
  //   链3=通用减标点。
  ['symboliclogical'],
  // 关键词级黑名单（自研/云 WAF 的 strip 规则，symboliclogical 换算子才有效）——
  // 真机 CRS 下为负收益（942120 正则含 && / ||），降到第四位不占 MAX_CHAINS 名额。
  ['hexliterals', 'dash2hash'],
  ['scalarselectinline', 'unionvaluesrow', 'dash2hash'],
  // [D4 真机] scalarselectinline 组合链同样 2/19 打穿（#162 链对拍），备选；
  // 单独的 scalarselectinline 只消标量子查询的 SELECT，须配合 unionvaluesrow 才覆盖 UNION 形态。
];

/**
 * 关键词「静默过滤」场景的候选链（删除型规则：不返 403，只把 union/select/and/-- 删掉）。
 * 顺序依据实测（e2e/pentest-lab/bl）：插入式双写 + 注释符换 `#` 一条即可命中布尔面；
 * 单用 `keywordinterleave` 会因 `--` 被删而语法错误，故 dash2hash 必须同链。
 */
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

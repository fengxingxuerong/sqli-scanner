// WAF → 推荐 tamper 组合映射表（经验库，初版 7 类）。
// 所有插件名均为 TamperRegistry 已注册名（与 GET /api/tampers 一致），避免"推荐了不存在的 tamper"。
// [P0-FIX] 差异化：按 WAF 技术栈/检测引擎类型定制推荐组合，替代原 50 条相同通用组合。
// 分类策略：
//   · CDN/云 WAF（Cloudflare/AWS/Akamai/Azure/GCP/Fastly 等）：关键字+空格检测 → charencode+space2comment+randomcase
//   · OWASP 正则引擎（ModSecurity/NAXSI/Wordfence/DotDefender）：版本化注释绕过 → versionedkeywords+space2comment+randomcase
//   · 硬件/企业 WAF（F5/FortiWeb/Citrix/Radware/PaloAlto/Sophos/SonicWall）：百分比/编码绕过 → percentage+space2comment+randomcase
//   · 国内 WAF（Aliyun/SafeDog/Tencent/360/Yundun/Anquanbao 等）：编码+注释+大小写 → charencode+space2comment+randomcase+between
//   · Imperva/Incapsula：专用 securesphere → securesphere+space2comment+randomcase
import { assertRecommendNames } from './assertTamperNames.js';
export const WAF_RECOMMEND_MAP = {
  // —— CDN/云 WAF（关键字+空格检测）——
  Cloudflare: ['space2comment', 'charencode', 'randomcase'],
  AWS_WAF: ['charencode', 'space2comment', 'randomcase'],
  Aliyun_WAF: ['charencode', 'space2comment', 'randomcase', 'between'],
  Baidu_Yunjiasu: ['space2comment', 'charencode', 'randomcomments'],
  SafeDog: ['charencode', 'space2comment', 'between', 'equaltolike'],
  Tencent_WAF: ['space2comment', 'charencode', 'randomcase', 'between'],
  // —— OWASP 正则引擎（版本化注释绕过；ModSecurity 另叠加官方验证的
  //    uniontable+odbcbrace 链：TABLE 语句消除 SELECT/FROM（942270），
  //    ODBC 转义前缀令 libinjection 指纹失配（942100/942360），异常分归零）——
  // [P0-FIX 2026-09-10 实测更正] 原链含 space2comment（`/**/` 是 4 连非词字符 → 必被 942460 拦）
  // 与 versionedkeywords（`/*!...*/` 被 942500 定点检测），在 CRS v4.1.0 下是负收益。
  // 现按 e2e/waf-real 实测（5/5 场景、10 技术位、安全对照零误拦）重排：
  // dash2hash 减标点（942460/942431）→ hexliterals 抽引号锚点（942511/942200/942370）
  // → uniontable/odbcbrace 消除 SELECT/FROM 与 libinjection 指纹（942270/942100）
  ModSecurity: ['dash2hash', 'hexliterals', 'uniontable', 'odbcbrace'],
  Barracuda: ['space2comment', 'randomcase', 'charencode'],
  Akamai_Kona: ['charencode', 'randomcase', 'space2comment'],
  DenyAll: ['space2comment', 'randomcase', 'charencode'],
  Wordfence: ['versionedkeywords', 'space2comment', 'randomcase'],
  Sucuri: ['charencode', 'space2comment', 'randomcase'],
  NAXSI: ['versionedkeywords', 'space2comment', 'randomcase'],
  DotDefender: ['space2comment', 'randomcase', 'charencode'],
  BinarySec: ['versionedkeywords', 'space2comment', 'randomcase'],
  BlockDoS: ['charencode', 'space2comment', 'randomcase'],
  // —— 硬件/企业 WAF（百分比/编码绕过）——
  F5_BIG_IP: ['space2comment', 'randomcase', 'percentage', 'space2plus'],
  F5_TrafficShield: ['space2comment', 'randomcase', 'percentage', 'space2plus'],
  FortiWeb: ['space2comment', 'randomcase', 'percentage'],
  Imperva_Incapsula: ['securesphere', 'space2comment', 'randomcase'],
  Citrix_NetScaler: ['space2comment', 'randomcase', 'percentage', 'space2plus'],
  Cisco_ACE: ['space2comment', 'randomcase', 'charencode'],
  Radware_AppWall: ['space2comment', 'randomcase', 'percentage'],
  Sophos_UTM: ['percentage', 'space2comment', 'randomcase'],
  Qihoo_360: ['charencode', 'space2comment', 'randomcase', 'between'],
  // —— 国内 WAF（编码+注释+大小写+between）——
  HuaweiCloud_WAF: ['charencode', 'space2comment', 'randomcase', 'between'],
  UPYUN_WAF: ['charencode', 'space2comment', 'randomcase'],
  Wangsu_WAF: ['charencode', 'space2comment', 'randomcase'],
  AWS_CloudFront: ['charencode', 'randomcase', 'space2comment'],
  Azure_FrontDoor: ['charencode', 'randomcase', 'space2comment'],
  GCP_CloudArmor: ['charencode', 'randomcase', 'space2comment'],
  Airlock: ['percentage', 'space2comment', 'randomcase'],
  StackPath: ['charencode', 'space2comment', 'randomcase'],
  Edgecast: ['space2comment', 'randomcase', 'charencode'],
  Fastly: ['charencode', 'randomcase', 'space2comment'],
  PaloAlto: ['percentage', 'space2comment', 'randomcase'],
  Zscaler: ['charencode', 'space2comment', 'randomcase'],
  Comodo: ['space2comment', 'randomcase', 'charencode'],
  SiteLock: ['charencode', 'space2comment', 'randomcase'],
  SonicWall: ['percentage', 'space2comment', 'randomcase'],
  Wallarm: ['space2comment', 'randomcase', 'charencode'],
  Zenedge: ['charencode', 'space2comment', 'randomcase'],
  Teros: ['space2comment', 'randomcase', 'charencode'],
  WebKnight: ['versionedkeywords', 'space2comment', 'randomcase'],
  SecureIIS: ['space2comment', 'randomcase', 'charencode'],
  UrlScan: ['versionedkeywords', 'space2comment', 'randomcase'],
  ShadowDaemon: ['charencode', 'space2comment', 'randomcase'],
  ATS: ['space2comment', 'randomcase', 'charencode'],
  WTS: ['space2comment', 'randomcase', 'charencode'],
  Jiasule: ['charencode', 'space2comment', 'randomcase', 'between'],
  Anquanbao: ['charencode', 'space2comment', 'randomcase', 'between'],
  NSFOCUS: ['versionedkeywords', 'space2comment', 'randomcase'],
  Yunsuo: ['charencode', 'space2comment', 'randomcase'],
  Yundun: ['charencode', 'space2comment', 'randomcase', 'between'],
  SafeLine: ['versionedkeywords', 'space2comment', 'randomcase'],
  Anyu: ['charencode', 'space2comment', 'randomcase', 'between'],
  // —— 补齐 v2/v3 遗漏厂商（差异化 by 技术栈）——
  Bluedon: ['charencode', 'space2comment', 'randomcase'],
  Chuangyu: ['charencode', 'space2comment', 'randomcase'],
  Eisoo: ['charencode', 'space2comment', 'randomcase'],
  Janusec: ['versionedkeywords', 'space2comment', 'randomcase'],
  KnownSec_KSWAF: ['charencode', 'space2comment', 'randomcase', 'between'],
  Safe3: ['versionedkeywords', 'space2comment', 'randomcase'],
  // —— 通用拦截证据（generic_block / 自建正则黑名单）——
  // [P0-FIX 2026-09-10 实战实测] 关键词级黑名单（只拦 union/select/or/and 这类「词」）用
  // 编码/注释/大小写变形一律无效——词还在。实测唯一有效的是**换算子**：OR→||、AND→&&、=→RLIKE。
  // 同一靶场实测：默认链 0 检出，symboliclogical 直接命中 boolean（e2e/pentest-lab/waf-diag.mjs）。
  // 故 generic_block 的推荐链把算子替换排在最前。
  generic_block: ['symboliclogical', 'equaltorlike', 'space2comment', 'randomcase'],
  // —— 通用 fallback（未列入映射表的 WAF）——
  // 同样前置 symboliclogical：未知 WAF 往往是自建正则，换算子比变形命中率高。
  _default: ['symboliclogical', 'space2comment', 'randomcase', 'charencode'],
};

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
  ['dash2hash', 'hexliterals'],
  ['dash2hash'],
  ['symboliclogical'],
  // ↑ 恰好三条：chainVerify 的 MAX_CHAINS=3 只验前三条。
  //   链1=CRS 内容规则（减标点 + 去引号锚点）；链2=通用减标点；
  //   链3=关键词级黑名单（自研/云 WAF 的 strip 规则，symboliclogical 换算子才有效）。
  ['hexliterals', 'dash2hash'],
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

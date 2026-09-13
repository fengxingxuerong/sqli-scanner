// ============================================================================
// wafRecommendMap.js —— WAF → 推荐 tamper 组合映射表（纯数据，零依赖）
//
// 从 wafRecommend.js 抽离，[解循环依赖 2026-09-13]。
// 之所以要单独成文件：assertTamperNames.js 需要这张表做「推荐名是否已注册」的自检，
// 而 wafRecommend.js 又要调用 assertTamperNames —— 共享数据下沉后两边都依赖它，环即断。
// ============================================================================

// WAF → 推荐 tamper 组合映射表（经验库，初版 7 类）。
// 所有插件名均为 TamperRegistry 已注册名（与 GET /api/tampers 一致），避免"推荐了不存在的 tamper"。
// [P0-FIX] 差异化：按 WAF 技术栈/检测引擎类型定制推荐组合，替代原 50 条相同通用组合。
// 分类策略：
//   · CDN/云 WAF（Cloudflare/AWS/Akamai/Azure/GCP/Fastly 等）：关键字+空格检测 → charencode+space2comment+randomcase
//   · OWASP 正则引擎（ModSecurity/NAXSI/Wordfence/DotDefender）：版本化注释绕过 → versionedkeywords+space2comment+randomcase
//   · 硬件/企业 WAF（F5/FortiWeb/Citrix/Radware/PaloAlto/Sophos/SonicWall）：百分比/编码绕过 → percentage+space2comment+randomcase
//   · 国内 WAF（Aliyun/SafeDog/Tencent/360/Yundun/Anquanbao 等）：编码+注释+大小写 → charencode+space2comment+randomcase+between
//   · Imperva/Incapsula：专用 securesphere → securesphere+space2comment+randomcase
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

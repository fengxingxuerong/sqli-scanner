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
  ModSecurity: ['uniontable', 'odbcbrace', 'modsecurityversioned', 'versionedkeywords', 'space2comment'],
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
  // —— 通用 fallback（未列入映射表的 WAF）——
  _default: ['space2comment', 'randomcase', 'charencode'],
};

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

// WAF → 推荐 tamper 组合映射表（经验库，初版 7 类）。
// 所有插件名均为 TamperRegistry 已注册名（与 GET /api/tampers 一致），避免"推荐了不存在的 tamper"。
import { assertRecommendNames } from './assertTamperNames.js';
export const WAF_RECOMMEND_MAP = {
  Cloudflare: ['space2comment', 'randomcase', 'charencode'],
  ModSecurity: ['modsecurityversioned', 'versionedkeywords', 'space2comment'],
  AWS_WAF: ['charencode', 'randomcase', 'space2comment'],
  Aliyun_WAF: ['space2comment', 'randomcase', 'charencode'],
  Baidu_Yunjiasu: ['space2comment', 'randomcomments', 'randomcase'],
  SafeDog: ['charencode', 'space2comment', 'equaltolike'],
  Tencent_WAF: ['space2comment', 'randomcase', 'charencode'],
  // —— 以下 23 项为 WAF-v2 新增（保留 7 项不变）。
  // 推荐名全部取自 tamperRegistry 已注册清单；通用预设 medium = [space2comment, randomcase, charencode]，
  // 少数重点 WAF 做定制（F5/Citrix 加 space2plus、FortiWeb/Radware 加 percentage、Imperva 用 securesphere、SafeDog 保留 equaltolike）。
  Barracuda: ['space2comment', 'randomcase', 'charencode'],
  F5_BIG_IP: ['space2comment', 'randomcase', 'space2plus'],
  FortiWeb: ['space2comment', 'randomcase', 'percentage'],
  Imperva_Incapsula: ['securesphere', 'space2comment', 'randomcase'],
  Akamai_Kona: ['space2comment', 'randomcase', 'charencode'],
  DenyAll: ['space2comment', 'randomcase', 'charencode'],
  Wordfence: ['space2comment', 'randomcase', 'charencode'],
  Sucuri: ['space2comment', 'randomcase', 'charencode'],
  Citrix_NetScaler: ['space2comment', 'randomcase', 'space2plus'],
  Cisco_ACE: ['space2comment', 'randomcase', 'charencode'],
  Radware_AppWall: ['space2comment', 'randomcase', 'percentage'],
  Sophos_UTM: ['space2comment', 'randomcase', 'charencode'],
  Qihoo_360: ['space2comment', 'randomcase', 'charencode'],
  NAXSI: ['space2comment', 'randomcase', 'charencode'],
  DotDefender: ['space2comment', 'randomcase', 'charencode'],
  BinarySec: ['space2comment', 'randomcase', 'charencode'],
  BlockDoS: ['space2comment', 'randomcase', 'charencode'],
  Bluedon: ['space2comment', 'randomcase', 'charencode'],
  Chuangyu: ['space2comment', 'randomcase', 'charencode'],
  Eisoo: ['space2comment', 'randomcase', 'charencode'],
  Janusec: ['space2comment', 'randomcase', 'charencode'],
  KnownSec_KSWAF: ['space2comment', 'randomcase', 'charencode'],
  Safe3: ['space2comment', 'randomcase', 'charencode'],
};

/**
 * 依据识别到的 WAF 候选，给出推荐 tamper 组合（仅推荐，不自动套用）。
 * @param {Array<{vendor:string, confidence:number, evidence:string}>} vendors WafIdentifier.identify 结果
 * @returns {Array<{vendor:string, plugins:string[]}>} 仅保留命中映射且 plugins 非空的项
 */
export function recommend(vendors) {
  const arr = Array.isArray(vendors) ? vendors : [];
  return arr
    .map((v) => ({ vendor: v.vendor, plugins: WAF_RECOMMEND_MAP[v.vendor] || [] }))
    .filter((s) => s.plugins.length > 0);
}

export default recommend;

// —— WAF-v2 启动期静态断言（fail-fast）：服务启动/测试加载即校验推荐名全部 ∈ tamperRegistry，
// 防止误写未注册名（recommend() 函数体不变，铁律）。
assertRecommendNames();

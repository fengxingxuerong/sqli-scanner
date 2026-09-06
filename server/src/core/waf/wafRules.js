// WAF 指纹规则库（内置轻量规则，零第三方依赖）。
// 数据来源：指纹阶段已抓取的 baseline 响应（status / headers / body），不再额外发包。
// 每个 matcher 命中即记该 vendor；confidence 按命中 matcher 数估算（初版：命中即 0.8+，多匹配升级）。
// 覆盖 62 家 WAF/CDN 指纹、共 126 条 matcher（v1 内置 7 类 → v2/v3 增量扩充至 62，与 wafRecommend 映射表同步维护）。
export const WAF_RULES = {
  Cloudflare: {
    name: 'Cloudflare',
    matchers: [
      { type: 'header', key: 'cf-ray' }, // 存在即特征
      { type: 'header', key: 'server', test: /cloudflare/i },
    ],
  },
  ModSecurity: {
    name: 'ModSecurity',
    matchers: [
      { type: 'body', test: /modsecurity/i },
      { type: 'header', key: 'server', test: /mod_security|modsecurity/i },
      { type: 'status', test: /^406$|^501$/ },
    ],
  },
  AWS_WAF: {
    name: 'AWS WAF',
    matchers: [
      { type: 'header', key: 'x-amzn-requestid' },
      { type: 'body', test: /request blocked by aws waf|the request could not be satisfied/i },
    ],
  },
  Aliyun_WAF: {
    name: '阿里云 WAF',
    matchers: [
      { type: 'header', key: 'server', test: /aliyun/i },
      { type: 'body', test: /阿里云|aliyun.*waf/i },
    ],
  },
  Baidu_Yunjiasu: {
    name: '百度云加速',
    matchers: [
      { type: 'header', key: 'server', test: /bws|baidu/i },
      { type: 'header', key: 'via', test: /yunjiasu|baidu/i },
    ],
  },
  SafeDog: {
    name: '安全狗',
    matchers: [
      { type: 'header', key: 'server', test: /safedog/i },
      { type: 'header', key: 'x-powered-by-safedog' },
    ],
  },
  Tencent_WAF: {
    name: '腾讯云 WAF',
    matchers: [
      { type: 'header', key: 'server', test: /tencent|stgw/i },
      { type: 'header', key: 'x-ws-request-id' },
    ],
  },
  // —— 以下 23 项为 WAF-v2 新增（保留 7 项不变）。
  // 铁律（坑 A）：WafIdentifier 仅支持 type:'header'|'body'|'status'，
  // 故 cookie 特征一律用 header(set-cookie) 表达，server 特征用 header(server) 表达，
  // 绝不使用非法的 type:'cookie' / type:'server'，也不使用 RegExp 形式的 key（getHeader 仅做精确小写匹配）。
  Barracuda: {
    name: 'Barracuda',
    matchers: [
      { type: 'header', key: 'server', test: /barracuda/i },
    ],
  },
  F5_BIG_IP: {
    name: 'F5 BIG-IP',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /bigipserver/i },
      { type: 'header', key: 'server', test: /big[- ]?ip/i },
    ],
  },
  FortiWeb: {
    name: 'FortiWeb',
    matchers: [
      { type: 'header', key: 'server', test: /fortiweb/i },
    ],
  },
  Imperva_Incapsula: {
    name: 'Imperva/Incapsula',
    matchers: [
      { type: 'header', key: 'x-iinfo' },
      { type: 'body', test: /incapsula/i },
    ],
  },
  Akamai_Kona: {
    name: 'Akamai Kona',
    matchers: [
      { type: 'header', key: 'server', test: /akamai/i },
    ],
  },
  DenyAll: {
    name: 'DenyAll',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /denyall_/i },
      { type: 'body', test: /denyall/i },
    ],
  },
  Wordfence: {
    name: 'Wordfence',
    matchers: [
      { type: 'body', test: /wordfence/i },
      { type: 'header', key: 'server', test: /wordfence/i },
    ],
  },
  Sucuri: {
    name: 'Sucuri',
    matchers: [
      { type: 'header', key: 'x-sucuri-id' },
      { type: 'header', key: 'server', test: /sucuri/i },
    ],
  },
  Citrix_NetScaler: {
    name: 'Citrix NetScaler',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /^nsc_/i },
      { type: 'header', key: 'via', test: /ns-cache/i },
    ],
  },
  Cisco_ACE: {
    name: 'Cisco ACE',
    matchers: [
      { type: 'header', key: 'server', test: /\bace\b/i },
    ],
  },
  Radware_AppWall: {
    name: 'Radware AppWall',
    matchers: [
      { type: 'header', key: 'server', test: /radware/i },
    ],
  },
  Sophos_UTM: {
    name: 'Sophos UTM',
    matchers: [
      { type: 'header', key: 'server', test: /sophos/i },
      { type: 'body', test: /sophos/i },
    ],
  },
  Qihoo_360: {
    name: 'Qihoo 360',
    matchers: [
      { type: 'body', test: /360webscan|qihoo/i },
    ],
  },
  NAXSI: {
    name: 'NAXSI',
    matchers: [
      { type: 'body', test: /blocked by naxsi/i },
    ],
  },
  DotDefender: {
    name: 'DotDefender',
    matchers: [
      { type: 'header', key: 'x-dotdefender' },
      { type: 'header', key: 'server', test: /dotdefender/i },
    ],
  },
  BinarySec: {
    name: 'BinarySec',
    matchers: [
      { type: 'header', key: 'server', test: /binarysec/i },
    ],
  },
  BlockDoS: {
    name: 'BlockDoS',
    matchers: [
      { type: 'body', test: /blockdos/i },
    ],
  },
  Bluedon: {
    name: 'Bluedon',
    matchers: [
      { type: 'header', key: 'server', test: /bluedon/i },
      { type: 'body', test: /bluedon/i },
    ],
  },
  Chuangyu: {
    name: 'Chuangyu/Yunaq',
    matchers: [
      { type: 'body', test: /chuangyu|yunaq/i },
    ],
  },
  Eisoo: {
    name: 'Eisoo',
    matchers: [
      { type: 'header', key: 'server', test: /eisoo|esafe/i },
      { type: 'body', test: /eisoo/i },
    ],
  },
  Janusec: {
    name: 'Janusec',
    matchers: [
      { type: 'header', key: 'x-janusec' },
      { type: 'body', test: /janusec/i },
    ],
  },
  KnownSec_KSWAF: {
    name: 'KnownSec KS-WAF',
    matchers: [
      { type: 'header', key: 'server', test: /ks-waf/i },
      { type: 'body', test: /knownsec/i },
    ],
  },
  Safe3: {
    name: 'Safe3 WAF',
    matchers: [
      { type: 'body', test: /safe3 web application firewall/i },
    ],
  },
  // —— 以下 32 项为 WAF-v3 新增（保留既有 30 项不变，总 62 项，对标 sqlmap 130+ vendor 的子集）。
  // 铁律同前：仅使用 type:'header'|'body'|'status'；cookie 用 header(set-cookie) 表达；
  // 每条签名均有据可依（wafw00f / sqlmap identYwaf / 厂商拦截页实测特征）。
  // —— 云 WAF ——
  HuaweiCloud_WAF: {
    name: '华为云 WAF',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /^HWWAFSESID=/i }, // 华为云 WAF 会话 Cookie
      { type: 'header', key: 'server', test: /huaweicloudwaf|hwclouds/i }, // Server: HuaweiCloudWAF
      { type: 'body', test: /hwclouds\.com|hws_security@/i }, // 拦截页域名/联系方式
    ],
  },
  UPYUN_WAF: {
    name: '又拍云 WAF',
    matchers: [
      { type: 'header', key: 'server', test: /upyun/i },
      { type: 'header', key: 'via', test: /upyun/i },
      { type: 'header', key: 'x-via', test: /upyun/i },
    ],
  },
  Wangsu_WAF: {
    name: '网宿 WAF',
    matchers: [
      { type: 'header', key: 'server', test: /wangsu|chinanetcenter/i },
      { type: 'header', key: 'via', test: /wangsu|chinanetcenter/i },
      { type: 'body', test: /网宿|chinanetcenter/i },
    ],
  },
  AWS_CloudFront: {
    name: 'AWS CloudFront',
    matchers: [
      { type: 'header', key: 'x-amz-cf-id' }, // 存在即特征（CloudFront 请求令牌）
      { type: 'header', key: 'x-amz-cf-pop' },
      { type: 'header', key: 'server', test: /cloudfront/i },
      { type: 'header', key: 'via', test: /cloudfront\.net/i },
    ],
  },
  Azure_FrontDoor: {
    name: 'Azure Front Door',
    matchers: [
      { type: 'header', key: 'x-azure-ref' }, // 存在即特征
      { type: 'header', key: 'x-azure-fdid' },
      { type: 'header', key: 'via', test: /azure/i },
    ],
  },
  GCP_CloudArmor: {
    name: 'GCP Cloud Armor',
    matchers: [
      { type: 'header', key: 'via', test: /1\.1 google/i }, // Google 边缘网络
      { type: 'header', key: 'server', test: /google frontend/i },
      { type: 'body', test: /google cloud armor|malformed or illegal request/i }, // 拦截页特征
    ],
  },
  // —— 设备 / 软件 WAF ——
  Airlock: {
    name: 'Airlock',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /^al[_-]?(sess|lb)=/i }, // AL-SESS / AL_LB Cookie
      { type: 'header', key: 'x-airlock-trace' },
      { type: 'body', test: /server detected a syntax error in your request/i },
    ],
  },
  StackPath: {
    name: 'StackPath',
    matchers: [
      { type: 'body', test: /<title>stackpath[^<]*<\/title>/i },
      { type: 'body', test: /protected by.*stackpath/i },
      { type: 'header', key: 'server', test: /stackpath/i },
    ],
  },
  Edgecast: {
    name: 'EdgeCast WAF',
    matchers: [
      { type: 'header', key: 'server', test: /^ec(acc|d|s)/i }, // ECAcc / ECDF / ECS 前缀
      { type: 'header', key: 'x-ec-p' },
    ],
  },
  Fastly: {
    name: 'Fastly',
    matchers: [
      { type: 'header', key: 'x-fastly-request-id' }, // 存在即特征
      { type: 'header', key: 'x-served-by', test: /^cache-[a-z]{3}\d+-[A-Z]{3}/i },
      { type: 'header', key: 'server', test: /fastly/i },
    ],
  },
  PaloAlto: {
    name: 'Palo Alto',
    matchers: [
      { type: 'body', test: /palo alto next generation security platform/i },
      { type: 'body', test: /has been blocked in accordance with company policy/i },
    ],
  },
  Zscaler: {
    name: 'Zscaler',
    matchers: [
      { type: 'header', key: 'server', test: /zscaler/i },
      { type: 'body', test: /access denied.{0,10}?accenture policy/i },
      { type: 'body', test: /policies\.accenture\.com|zscaler to protect you from internet threats/i },
    ],
  },
  Comodo: {
    name: 'Comodo WAF',
    matchers: [
      { type: 'header', key: 'server', test: /protected by comodo waf/i },
    ],
  },
  SiteLock: {
    name: 'SiteLock TrueShield',
    matchers: [
      { type: 'body', test: /sitelock will remember you|sitelock incident id/i },
      { type: 'body', test: /sitelock is leader in business website security services/i },
    ],
  },
  SonicWall: {
    name: 'SonicWall',
    matchers: [
      { type: 'header', key: 'server', test: /sonicwall/i },
      { type: 'body', test: /nsa_banner/i },
    ],
  },
  Wallarm: {
    name: 'Wallarm',
    matchers: [
      { type: 'header', key: 'server', test: /nginx[-_]wallarm/i },
      { type: 'header', key: 'x-wallarm' },
    ],
  },
  Zenedge: {
    name: 'Zenedge',
    matchers: [
      { type: 'header', key: 'server', test: /zenedge/i },
      { type: 'header', key: 'x-zen-fury' },
      { type: 'body', test: /\/__zenedge\//i },
    ],
  },
  Teros: {
    name: 'Teros',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /^st8(id|_wat|_wlf)/i },
    ],
  },
  F5_TrafficShield: {
    name: 'F5 TrafficShield',
    matchers: [
      { type: 'header', key: 'server', test: /f5[- ]trafficshield/i },
      { type: 'header', key: 'set-cookie', test: /^ASINFO=/i },
    ],
  },
  WebKnight: {
    name: 'WebKnight',
    matchers: [
      { type: 'status', test: /^999$/ }, // WebKnight 拦截返回 "999 No Hacking"
      { type: 'body', test: /webknight application firewall alert|aqtronix.{0,10}?webknight/i },
    ],
  },
  SecureIIS: {
    name: 'SecureIIS',
    matchers: [
      { type: 'body', test: /secureiis is an internet security application/i },
    ],
  },
  UrlScan: {
    name: 'Microsoft UrlScan',
    matchers: [
      { type: 'body', test: /rejected[-_]by[-_]urlscan/i },
      { type: 'header', key: 'location', test: /rejected-by-urlscan/i },
    ],
  },
  // —— 开源 WAF ——
  ShadowDaemon: {
    name: 'Shadow Daemon',
    matchers: [
      { type: 'body', test: /request forbidden by administrative rules/i },
      { type: 'body', test: /<h\d{1}>\d{3}\.forbidden<\/h\d{1}>/i },
    ],
  },
  ATS: {
    name: 'Apache Traffic Server',
    matchers: [
      { type: 'header', key: 'server', test: /^ats\/|apache traffic server/i }, // Server: ATS/7.1.0
      { type: 'header', key: 'via', test: /\(ats\b|apachetrafficserver/i },
    ],
  },
  WTS: {
    name: 'WTS WAF',
    matchers: [
      { type: 'header', key: 'server', test: /wts\//i }, // Server: wts/0.4.7
      { type: 'body', test: />wts-waf/i },
    ],
  },
  // —— 国内补充高价值 WAF ——
  Jiasule: {
    name: '加速乐 Jiasule',
    matchers: [
      { type: 'header', key: 'server', test: /jiasule-waf/i },
      { type: 'header', key: 'set-cookie', test: /__jsluid=|jsl_tracking/i },
      { type: 'body', test: /notice-jiasule|static\.jiasule\.com/i },
    ],
  },
  Anquanbao: {
    name: '安全宝 Anquanbao',
    matchers: [
      { type: 'header', key: 'x-powered-by-anquanbao' }, // X-Powered-By-Anquanbao: MISS
      { type: 'body', test: /aqb_cc\/error\//i },
    ],
  },
  NSFOCUS: {
    name: '绿盟 NSFOCUS',
    matchers: [
      { type: 'header', key: 'server', test: /nsfocus/i },
      { type: 'body', test: /nsfocus/i },
    ],
  },
  Yunsuo: {
    name: '云锁 Yunsuo',
    matchers: [
      { type: 'header', key: 'set-cookie', test: /yunsuo_session/i },
      { type: 'body', test: /<img class="yunsuologo"/i },
    ],
  },
  Yundun: {
    name: '云盾 Yundun',
    matchers: [
      { type: 'header', key: 'server', test: /yundun/i },
      { type: 'header', key: 'x-cache', test: /yundun/i },
      { type: 'header', key: 'set-cookie', test: /^yd_cookie=/i },
      { type: 'body', test: /blocked by yundun cloud waf/i },
    ],
  },
  SafeLine: {
    name: '雷池 SafeLine',
    matchers: [
      { type: 'body', test: /safeline|<!--\s*event[_-]?id:/i },
      { type: 'header', key: 'server', test: /safeline/i },
    ],
  },
  Anyu: {
    name: '安域 Anyu',
    matchers: [
      { type: 'body', test: /your access has been intercepted by anyu/i },
      { type: 'body', test: /anyu.{0,10}?the green channel/i },
    ],
  },
};

// ============================================================================
// [P3-WAF] 启动期结构断言（fail-fast）：WafIdentifier.matchOne 按 type 三分发
// （header 需要 key，body/status 需要 test 正则），任何不合结构的规则都会被
// 静默跳过（永远不命中）——与其上线后无声失效，不如启动时立即报错。
for (const [vendor, rule] of Object.entries(WAF_RULES)) {
  if (!rule || typeof rule !== 'object' || !Array.isArray(rule.matchers) || rule.matchers.length === 0) {
    throw new Error(`[wafRules] ${vendor} 缺少非空 matchers 数组`);
  }
  for (const m of rule.matchers) {
    if (!m || typeof m !== 'object') {
      throw new Error(`[wafRules] ${vendor} 存在非对象 matcher`);
    }
    if (m.type === 'header') {
      if (typeof m.key !== 'string' || m.key.length === 0) {
        throw new Error(`[wafRules] ${vendor} 的 header matcher 缺少 key`);
      }
      if (m.test && !(m.test instanceof RegExp)) {
        throw new Error(`[wafRules] ${vendor} 的 header matcher test 必须是正则`);
      }
    } else if (m.type === 'body' || m.type === 'status') {
      if (!(m.test instanceof RegExp)) {
        throw new Error(`[wafRules] ${vendor} 的 ${m.type} matcher 缺少 test 正则`);
      }
    } else {
      throw new Error(`[wafRules] ${vendor} 存在非法 matcher.type: ${String(m.type)}（仅允许 header/body/status）`);
    }
  }
}

export default WAF_RULES;

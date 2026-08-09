// WAF 指纹规则库（内置轻量规则，零第三方依赖）。
// 数据来源：指纹阶段已抓取的 baseline 响应（status / headers / body），不再额外发包。
// 每个 matcher 命中即记该 vendor；confidence 按命中 matcher 数估算（初版：命中即 0.8+，多匹配升级）。
// 覆盖 7 类常见 WAF：Cloudflare / ModSecurity / AWS WAF / 阿里云 WAF / 百度云加速 / 安全狗 / 腾讯云 WAF。
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
  // —— WAF-v3 新增 13 项（保留既有 30 项不变）。签名均取自各厂商公开响应头/页特征。
  Reblaze: {
    name: 'Reblaze',
    matchers: [{ type: 'header', key: 'server', test: /reblaze/i }],
  },
  StackPath: {
    name: 'StackPath',
    matchers: [{ type: 'header', key: 'server', test: /stackpath/i }],
  },
  SiteGround: {
    name: 'SiteGround',
    matchers: [{ type: 'header', key: 'server', test: /siteground/i }],
  },
  GoDaddy: {
    name: 'GoDaddy',
    matchers: [{ type: 'header', key: 'server', test: /godaddy/i }],
  },
  Ergon_Airlock: {
    name: 'Ergon Airlock',
    matchers: [{ type: 'header', key: 'server', test: /airlock/i }],
  },
  Armor: {
    name: 'Armor WAF',
    matchers: [
      { type: 'header', key: 'x-armor' },
      { type: 'header', key: 'server', test: /armor/i },
    ],
  },
  Wallarm: {
    name: 'Wallarm',
    matchers: [
      { type: 'header', key: 'x-wallarm-id' },
      { type: 'header', key: 'server', test: /wallarm/i },
    ],
  },
  Profense: {
    name: 'Proventia / ProFense',
    matchers: [
      { type: 'header', key: 'x-profense' },
      { type: 'header', key: 'server', test: /profense/i },
    ],
  },
  Edgecast: {
    name: 'Edgecast / Verizon',
    matchers: [
      { type: 'header', key: 'x-ec' },
      { type: 'header', key: 'server', test: /edgecast/i },
    ],
  },
  Fastly: {
    name: 'Fastly',
    matchers: [
      { type: 'header', key: 'x-fastly' },
      { type: 'header', key: 'server', test: /fastly/i },
    ],
  },
  Azure_FrontDoor: {
    name: 'Azure Front Door / WAF',
    matchers: [{ type: 'header', key: 'x-azure-ref' }],
  },
  Limelight: {
    name: 'Limelight / Edgio',
    matchers: [{ type: 'header', key: 'server', test: /llnw|limelight/i }],
  },
  PaloAlto: {
    name: 'Palo Alto PAN-OS',
    matchers: [{ type: 'header', key: 'server', test: /pan-os|phosphorus/i }],
  },
};

export default WAF_RULES;

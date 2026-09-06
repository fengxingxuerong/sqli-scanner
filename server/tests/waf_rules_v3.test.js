// WAF-v3 扩库护栏测试（T-WAFv3-1）：新增 32 vendor 识别准确 + 零误报 + 数量护栏 + 推荐映射合法
// 新增覆盖：云 WAF（华为云/又拍云/网宿/CloudFront/Azure Front Door/GCP Cloud Armor）、
// 设备 WAF（Airlock/StackPath/EdgeCast/Fastly/Palo Alto/Zscaler/Comodo/SiteLock/SonicWall/
// Wallarm/Zenedge/Teros/F5 TrafficShield/WebKnight/SecureIIS/UrlScan）、
// 开源（Shadow Daemon/ATS/WTS）、国内（加速乐/安全宝/绿盟/云锁/云盾/雷池/安域）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { WAF_RULES } from '../src/core/waf/wafRules.js';
import { recommend, WAF_RECOMMEND_MAP } from '../src/core/waf/wafRecommend.js';
import { tamperRegistry } from '../src/core/tamper/index.js';

const REGISTERED = new Set(tamperRegistry.list().map((t) => t.name));

// 每条指纹用一个「代表性样本」断言识别准确（响应头/拦截页特征均取自真实拦截页）
const SAMPLES = [
  { vendor: 'HuaweiCloud_WAF', resp: { status: 403, headers: { 'set-cookie': 'HWWAFSESID=abc123' }, body: '' }, desc: 'HWWAFSESID Cookie' },
  { vendor: 'HuaweiCloud_WAF', resp: { status: 403, headers: { server: 'HuaweiCloudWAF' }, body: 'hwclouds.com' }, desc: 'Server + 拦截页域名' },
  { vendor: 'UPYUN_WAF', resp: { status: 200, headers: { server: 'nginx/1.20', via: '1.1 varnish, 1.1 upyun' }, body: '' }, desc: 'Via: upyun' },
  { vendor: 'Wangsu_WAF', resp: { status: 403, headers: { server: 'Wangsu CDN' }, body: 'chinanetcenter' }, desc: 'Server/body 网宿特征' },
  { vendor: 'AWS_CloudFront', resp: { status: 200, headers: { 'x-amz-cf-id': 'sX5QSkbAzSwd', server: 'CloudFront' }, body: '' }, desc: 'X-Amz-Cf-Id' },
  { vendor: 'Azure_FrontDoor', resp: { status: 200, headers: { 'x-azure-ref': '20260814T100000Z' }, body: '' }, desc: 'X-Azure-Ref' },
  { vendor: 'GCP_CloudArmor', resp: { status: 403, headers: { via: '1.1 google' }, body: 'Your client has issued a malformed or illegal request' }, desc: 'Via: 1.1 google + 拦截文案' },
  { vendor: 'Airlock', resp: { status: 403, headers: { 'set-cookie': 'AL-SESS=abc' }, body: '' }, desc: 'AL-SESS Cookie' },
  { vendor: 'StackPath', resp: { status: 403, headers: {}, body: '<title>StackPath</title> Protected by StackPath' }, desc: '拦截页 title+签名' },
  { vendor: 'Edgecast', resp: { status: 400, headers: { server: 'ECDF (iad/xxxx)' }, body: '' }, desc: 'Server: ECDF' },
  { vendor: 'Fastly', resp: { status: 200, headers: { 'x-fastly-request-id': 'b7fef41e92da', 'x-served-by': 'cache-sjc1000133-SJC' }, body: '' }, desc: 'X-Fastly-Request-ID' },
  { vendor: 'PaloAlto', resp: { status: 403, headers: {}, body: 'Palo Alto Next Generation Security Platform' }, desc: 'Palo Alto 拦截页' },
  { vendor: 'Zscaler', resp: { status: 403, headers: { server: 'ZScaler' }, body: 'Zscaler to protect you from internet threats' }, desc: 'Server: ZScaler' },
  { vendor: 'Comodo', resp: { status: 403, headers: { server: 'Protected by COMODO WAF' }, body: '' }, desc: 'Server: Protected by COMODO WAF' },
  { vendor: 'SiteLock', resp: { status: 403, headers: {}, body: 'SiteLock incident ID: 12345' }, desc: 'SiteLock 拦截页' },
  { vendor: 'SonicWall', resp: { status: 403, headers: { server: 'SonicWALL' }, body: '<div class="nsa_banner">' }, desc: 'Server: SonicWALL' },
  { vendor: 'Wallarm', resp: { status: 403, headers: { server: 'nginx-wallarm' }, body: '' }, desc: 'Server: nginx-wallarm' },
  { vendor: 'Zenedge', resp: { status: 403, headers: { server: 'ZENEDGE' }, body: '/__zenedge/assets/' }, desc: 'Server: ZENEDGE' },
  { vendor: 'Teros', resp: { status: 200, headers: { 'set-cookie': 'st8id=abc123' }, body: '' }, desc: 'st8id Cookie' },
  { vendor: 'F5_TrafficShield', resp: { status: 403, headers: { server: 'F5-TrafficShield' }, body: '' }, desc: 'Server: F5-TrafficShield' },
  { vendor: 'WebKnight', resp: { status: 999, headers: { server: 'WWW Server/1.1' }, body: 'AQTRONIX WebKnight' }, desc: '状态 999 + WebKnight' },
  { vendor: 'SecureIIS', resp: { status: 403, headers: {}, body: 'SecureIIS is an internet security application' }, desc: 'SecureIIS 拦截页' },
  { vendor: 'UrlScan', resp: { status: 302, headers: { location: '/Rejected-By-UrlScan' }, body: '' }, desc: 'Rejected-By-UrlScan' },
  { vendor: 'ShadowDaemon', resp: { status: 403, headers: {}, body: '<h1>403 forbidden</h1> request forbidden by administrative rules' }, desc: 'Shadow Daemon 拦截页' },
  { vendor: 'ATS', resp: { status: 200, headers: { server: 'ATS/9.0' }, body: '' }, desc: 'Server: ATS/9.0' },
  { vendor: 'WTS', resp: { status: 403, headers: { server: 'wts/0.4.7' }, body: '' }, desc: 'Server: wts/0.4.7' },
  { vendor: 'Jiasule', resp: { status: 403, headers: { server: 'jiasule-WAF' }, body: '' }, desc: 'Server: jiasule-WAF' },
  { vendor: 'Anquanbao', resp: { status: 405, headers: { 'x-powered-by-anquanbao': 'MISS from uni-tj-ky-sb3' }, body: '' }, desc: 'X-Powered-By-Anquanbao' },
  { vendor: 'NSFOCUS', resp: { status: 403, headers: { server: 'NSFocus' }, body: '' }, desc: 'Server: NSFocus' },
  { vendor: 'Yunsuo', resp: { status: 200, headers: { 'set-cookie': 'yunsuo_session=abc' }, body: '' }, desc: 'yunsuo_session Cookie' },
  { vendor: 'Yundun', resp: { status: 403, headers: { server: 'YUNDUN' }, body: 'Blocked by YUNDUN Cloud WAF' }, desc: 'Server: YUNDUN' },
  { vendor: 'SafeLine', resp: { status: 403, headers: {}, body: '<!-- event_id: 0123456789abcdef0123456789abcdef -->' }, desc: '雷池 event_id 注释' },
  { vendor: 'Anyu', resp: { status: 403, headers: {}, body: 'your access has been intercepted by anyu' }, desc: '安域拦截文案' },
];

test('WAF-v3 数量护栏：62 项（30 旧 + 32 新）', () => {
  const n = Object.keys(WAF_RULES).length;
  assert.equal(n, 62, `当前 ${n} 条，应为 62`);
});

test('新增 vendor 全部能识别（逐条代表性样本）', () => {
  const id = new WafIdentifier();
  for (const { vendor, resp, desc } of SAMPLES) {
    const r = id.identify(resp);
    const hit = r.find((c) => c.vendor === vendor);
    assert.ok(hit, `应识别 ${vendor}（${desc}）`);
    assert.ok(hit.confidence >= 0.8, `${vendor} 置信度应 >= 0.8`);
  }
});

test('无 WAF 特征响应 → 返回 []（零误报回归，含新规则）', () => {
  const id = new WafIdentifier();
  const r = id.identify({ status: 200, headers: { server: 'nginx', 'content-type': 'text/html' }, body: '<html><body>hello world</body></html>' });
  assert.deepEqual(r, [], '干净响应不应误报任何 WAF（含新增 32 条）');
});

test('新增 vendor 推荐映射全部合法且 recommend 非空', () => {
  const input = Object.keys(WAF_RECOMMEND_MAP).map((v) => ({ vendor: v, confidence: 0.9, evidence: 'x' }));
  const sug = recommend(input);
  assert.equal(sug.length, Object.keys(WAF_RECOMMEND_MAP).length, '全部 vendor 都应被推荐');
  for (const s of sug) {
    assert.ok(s.plugins.length > 0, `vendor="${s.vendor}" 推荐应非空`);
    for (const p of s.plugins) assert.ok(REGISTERED.has(p), `vendor="${s.vendor}" 引用未注册插件 "${p}"`);
  }
});

test('新增与既有 vendor 的 matcher 无空规则（每条至少一个 matcher）', () => {
  for (const [vendor, rule] of Object.entries(WAF_RULES)) {
    assert.ok(Array.isArray(rule.matchers) && rule.matchers.length > 0, `${vendor} 应至少一个 matcher`);
  }
});

// WAF-v2 扩库护栏测试（T-WAFv2-2）：识别准确 + 零误报 + 推荐名合法 + 数量护栏 + 多 WAF 串联
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { WAF_RULES } from '../src/core/waf/wafRules.js';
import { assertRecommendNames } from '../src/core/waf/assertTamperNames.js';
import { tamperRegistry } from '../src/core/tamper/index.js';

test('启动期静态断言：所有推荐名均已在注册表（不抛错）', () => {
  assert.equal(assertRecommendNames(), true);
  // 反向：传入过小的集合应抛错（契约兜底）
  assert.throws(() => assertRecommendNames(new Set(['space2comment'])));
});

test('WAF_RULES 数量护栏：>= 28（扩库到约 43）', () => {
  const n = Object.keys(WAF_RULES).length;
  assert.ok(n >= 28, `当前 ${n} 条，应 >= 28`);
  assert.ok(n <= 45, `当前 ${n} 条，不应超过 45`);
});

test('抽样新 vendor 识别准确（Imperva_Incapsula / F5_BIG_IP / FortiWeb）', () => {
  const id = new WafIdentifier();

  const r1 = id.identify({ status: 200, headers: { 'x-iinfo': 'abc123' }, body: '' });
  assert.ok(r1.find((c) => c.vendor === 'Imperva_Incapsula'), '应识别 Imperva/Incapsula (x-iinfo)');

  const r2 = id.identify({ status: 200, headers: { 'set-cookie': 'BIGipServer=pool1' }, body: '' });
  assert.ok(r2.find((c) => c.vendor === 'F5_BIG_IP'), '应识别 F5 BIG-IP (set-cookie)');

  const r3 = id.identify({ status: 200, headers: { server: 'FortiWeb' }, body: '' });
  assert.ok(r3.find((c) => c.vendor === 'FortiWeb'), '应识别 FortiWeb (server)');
});

test('无 WAF 特征响应 → 返回 []（零误报）', () => {
  const id = new WafIdentifier();
  const r = id.identify({ status: 200, headers: { server: 'nginx', 'content-type': 'text/html' }, body: '<html><body>hello</body></html>' });
  assert.deepEqual(r, [], '干净响应不应误报任何 WAF');
});

test('多 WAF 串联样本 → 返回多个候选', () => {
  const id = new WafIdentifier();
  // 同时带 Imperva(x-iinfo) 与 F5(set-cookie) 特征
  const r = id.identify({
    status: 200,
    headers: { 'x-iinfo': 'abc', 'set-cookie': 'BIGipServer=pool1', server: 'nginx' },
    body: '',
  });
  const vendors = r.map((c) => c.vendor);
  assert.ok(vendors.includes('Imperva_Incapsula'), '应含 Imperva');
  assert.ok(vendors.includes('F5_BIG_IP'), '应含 F5');
  assert.ok(r.length >= 2, '多 WAF 串联应返回多个候选');
});

test('原 7 vendor 行为不变（Cloudflare 仍识别）', () => {
  const id = new WafIdentifier();
  const r = id.identify({ status: 200, headers: { 'cf-ray': 'x', server: 'cloudflare' }, body: '' });
  assert.ok(r.find((c) => c.vendor === 'Cloudflare'), '原 7 vendor 不受影响');
});

// 顺带固化：注册表确有 62 插件（扩库依赖的真相源）
test('tamper 注册表规模 >= 62（扩库前提）', () => {
  assert.ok(tamperRegistry.list().length >= 62, `当前 ${tamperRegistry.list().length} 个插件`);
});

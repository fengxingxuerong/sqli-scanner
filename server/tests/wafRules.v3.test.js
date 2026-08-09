// WAF 指纹规则库扩充（v3 新增 13 厂商）回归测试
// 每个厂商用匹配其签名的合成 baseline 响应断言可被识别；中性响应该返回 []。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { WAF_RULES } from '../src/core/waf/wafRules.js';

const NEW_VENDORS = [
  'Reblaze',
  'StackPath',
  'SiteGround',
  'GoDaddy',
  'Ergon_Airlock',
  'Armor',
  'Wallarm',
  'Profense',
  'Edgecast',
  'Fastly',
  'Azure_FrontDoor',
  'Limelight',
  'PaloAlto',
];

// 各厂商用于"命中"的合成响应（至少命中其一个 matcher）
const HIT_RESPONSES = {
  Reblaze: { headers: { server: 'Reblaze/1.0' } },
  StackPath: { headers: { server: 'StackPath' } },
  SiteGround: { headers: { server: 'SiteGround' } },
  GoDaddy: { headers: { server: 'Godaddy' } },
  Ergon_Airlock: { headers: { server: 'Airlock' } },
  Armor: { headers: { 'x-armor': '1' } },
  Wallarm: { headers: { 'x-wallarm-id': 'abc' } },
  Profense: { headers: { 'x-profense': '1' } },
  Edgecast: { headers: { 'x-ec': '1' } },
  Fastly: { headers: { 'x-fastly': '1' } },
  Azure_FrontDoor: { headers: { 'x-azure-ref': 'abc' } },
  Limelight: { headers: { server: 'LLNW' } },
  PaloAlto: { headers: { server: 'pan-os' } },
};

test('v3 新增 13 个 WAF 厂商规则均已注册', () => {
  for (const v of NEW_VENDORS) {
    assert.ok(WAF_RULES[v], `缺失规则: ${v}`);
  }
});

test('每个新增厂商用匹配签名均可被识别', () => {
  const id = new WafIdentifier();
  for (const v of NEW_VENDORS) {
    const resp = HIT_RESPONSES[v];
    const candidates = id.identify({
      status: 200,
      headers: resp.headers || {},
      body: resp.body || '',
    });
    const hit = candidates.find((c) => c.vendor === v);
    assert.ok(hit, `厂商 ${v} 应能被识别，实际候选=${JSON.stringify(candidates.map((c) => c.vendor))}`);
    assert.ok(hit.confidence >= 0.8, `厂商 ${v} 置信度应≥0.8`);
  }
});

test('中性响应（无任何 WAF 特征）返回空', () => {
  const id = new WafIdentifier();
  const candidates = id.identify({
    status: 200,
    headers: { server: 'nginx', 'content-type': 'text/html' },
    body: '<html>hello</html>',
  });
  assert.deepEqual(candidates, []);
});

test('多特征命中提升置信度（Wallarm 双特征 → 0.9）', () => {
  const id = new WafIdentifier();
  const candidates = id.identify({
    status: 200,
    headers: { 'x-wallarm-id': 'abc', server: 'Wallarm' },
    body: '',
  });
  const w = candidates.find((c) => c.vendor === 'Wallarm');
  assert.ok(w, 'Wallarm 应被识别');
  assert.equal(w.confidence, 0.9, '双特征命中置信度应为 0.9');
});

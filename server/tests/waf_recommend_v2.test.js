// WAF-v2 推荐映射护栏测试（T-WAFv2-2）：扩库后 recommend() 返回合法插件 + 过滤无映射 vendor
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recommend, WAF_RECOMMEND_MAP, WAF_VENDORS } from '../src/core/waf/wafRecommend.js';
import { tamperRegistry } from '../src/core/tamper/index.js';

const REGISTERED = new Set(tamperRegistry.list().map((t) => t.name));

test('扩库后每个 vendor 的推荐插件全部 ∈ tamperRegistry', () => {
  for (const [vendor, plugins] of Object.entries(WAF_RECOMMEND_MAP)) {
    for (const p of plugins || []) {
      assert.ok(REGISTERED.has(p), `vendor="${vendor}" 引用未注册插件 "${p}"`);
    }
  }
});

test('新增 vendor 推荐：返回 {vendor,plugins}[] 且 plugins 全合法', () => {
  const sug = recommend([{ vendor: 'F5_BIG_IP', confidence: 0.9, evidence: 'x' }]);
  assert.equal(sug.length, 1);
  assert.equal(sug[0].vendor, 'F5_BIG_IP');
  assert.ok(Array.isArray(sug[0].plugins) && sug[0].plugins.length > 0);
  for (const p of sug[0].plugins) assert.ok(REGISTERED.has(p), `未注册插件 ${p}`);
});

test('无映射 vendor 走 _default fallback（仍返回非空推荐）', () => {
  const sug = recommend([
    { vendor: 'UnknownVendor', confidence: 0.9, evidence: 'x' },
    { vendor: 'AWS_WAF', confidence: 0.9, evidence: 'x' },
  ]);
  // _default fallback 使 UnknownVendor 也返回非空推荐
  assert.equal(sug.length, 2);
  assert.ok(sug.some((s) => s.vendor === 'AWS_WAF'));
  assert.ok(sug.some((s) => s.vendor === 'UnknownVendor'));
  for (const s of sug) {
    assert.ok(s.plugins.length > 0);
  }
});

test('遍历全部 vendor：recommend 均返回非空且合法', () => {
  const input = WAF_VENDORS.map((v) => ({ vendor: v, confidence: 0.9, evidence: 'x' }));
  const sug = recommend(input);
  assert.equal(sug.length, WAF_VENDORS.length, '全部 vendor 都应被推荐');
  for (const s of sug) {
    assert.ok(s.plugins.length > 0);
    for (const p of s.plugins) assert.ok(REGISTERED.has(p));
  }
});

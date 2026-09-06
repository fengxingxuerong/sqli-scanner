// 测试 server/src/config/defaults.js 默认值完整性
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaults } from '../src/config/defaults.js';

test('默认值完整性（ratePerSec/concurrency/retry/timeoutMs）', () => {
  assert.equal(defaults.ratePerSec, 50);
  assert.equal(defaults.concurrency, 4);
  // [P0-FIX] 对标 sqlmap 默认：timeoutMs 30s、retry 3
  assert.equal(defaults.retry, 3);
  assert.equal(defaults.timeoutMs, 30000);
});

test('blindRobust 子对象结构', () => {
  const b = defaults.blindRobust;
  assert.equal(b.enabled, true);
  assert.equal(b.booleanSamples, 3);
  assert.equal(b.baselineSamples, 5);
  assert.equal(b.minStableRatio, 0.66);
  assert.equal(b.booleanSignificanceZ, 1.645);
  assert.equal(typeof b.adaptive, 'boolean');
});

test('wafEvasion 子对象结构', () => {
  const w = defaults.wafEvasion;
  assert.equal(w.tamper.enabled, false);
  assert.equal(w.autoRetry, false);
  assert.ok(Array.isArray(w.tamper.plugins));
});

test('oob 子对象结构', () => {
  const o = defaults.oob;
  assert.equal(o.enabled, false);
  assert.equal(o.httpPort, 8899);
  assert.equal(typeof o.callbackBase, 'string');
});

test('techniques 默认 4 类', () => {
  assert.deepEqual(defaults.techniques, ['union', 'error', 'boolean', 'time']);
});

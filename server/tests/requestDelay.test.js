import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';

// 去掉令牌桶限速干扰：把令牌池设到极大，使 acquire 不等待，专注测固定延时/jitter
function makeUnthrottledClient() {
  const c = new HttpClient();
  c.bucket.tokens = 1e9;
  c.bucket.capacity = 1e9;
  c.bucket.ratePerSec = 1e9;
  return c;
}

function stubInstance(c) {
  c.instance.request = async () => ({ data: 'ok', status: 200 });
}

test('默认 requestDelayMs=0（且 jitter 关闭）→ 连续请求几乎瞬时，无固定延时', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  const start = Date.now();
  for (let i = 0; i < 3; i++) await c.request({ method: 'GET', url: 'http://x/', headers: {} });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 200, `默认不应延时，实际 ${elapsed}ms`);
});

test('requestDelayMs=50 → 3 次请求总耗时 >=150ms（固定间隔生效）', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  const start = Date.now();
  for (let i = 0; i < 3; i++) {
    await c.request({ method: 'GET', url: 'http://x/', headers: {}, requestDelayMs: 50 });
  }
  const elapsed = Date.now() - start;
  // 3 次请求前各休眠 50ms → 至少 150ms（jitter 关闭，不叠加随机）
  assert.ok(elapsed >= 150, `固定延时应生效，实际 ${elapsed}ms`);
  assert.ok(elapsed < 400, `不应叠加随机延时（jitter 关），实际 ${elapsed}ms`);
});

test('requestDelayMs 与 jitter 叠加：delay=30 + jitter=40 → 3 次总耗时 >=90ms 且 <800ms', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  const start = Date.now();
  for (let i = 0; i < 3; i++) {
    await c.request({
      method: 'GET',
      url: 'http://x/',
      headers: {},
      requestDelayMs: 30,
      wafEvasion: { randomUA: false, jitterMs: 40, obfuscate: false },
    });
  }
  const elapsed = Date.now() - start;
  // 下界：3*(30+0)=90ms；上界：3*(30+40)=210ms，留容差到 800ms（含事件循环调度）
  assert.ok(elapsed >= 90, `叠加延时下界应 >=90ms，实际 ${elapsed}ms`);
  assert.ok(elapsed < 800, `叠加不应过久，实际 ${elapsed}ms`);
});

test('requestDelayMs 经 config 默认透传：未显式传时读 defaults（0），不延时', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  const start = Date.now();
  // 不传 requestDelayMs → 走 defaults.requestDelayMs（0）
  await c.request({ method: 'GET', url: 'http://x/', headers: {} });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 200, `未传时不延时，实际 ${elapsed}ms`);
});

test('实例级默认 requestDelayMs：未传 opts 时经全局默认生效（ScanManager 注入路径）', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  c.requestDelayMs = 50; // 模拟 ScanManager 按 config 注入实例默认
  const start = Date.now();
  for (let i = 0; i < 3; i++) {
    await c.request({ method: 'GET', url: 'http://x/', headers: {} }); // 不传 opts.requestDelayMs
  }
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= 150, `实例默认延时生效，实际 ${elapsed}ms`);
  assert.ok(elapsed < 500, `不应叠加随机延时，实际 ${elapsed}ms`);
});

test('opts.requestDelayMs 优先于实例默认：opts 覆盖实例值', async () => {
  const c = makeUnthrottledClient();
  stubInstance(c);
  c.requestDelayMs = 100; // 实例默认 100ms
  const start = Date.now();
  // 单次请求显式传 0 → 应瞬时（不受实例 100ms 默认影响）
  await c.request({ method: 'GET', url: 'http://x/', headers: {}, requestDelayMs: 0 });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 200, `opts=0 应覆盖实例默认，实际 ${elapsed}ms`);
});

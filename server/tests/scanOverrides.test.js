import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withScanOverrides } from '../src/core/httpClient.js';

// 记录每次 request 收到的完整 opts，用于断言包装注入行为
function makeRecorder() {
  const calls = [];
  return {
    calls,
    request: async (opts) => {
      calls.push(opts);
      return { data: 'ok', status: 200, headers: {} };
    },
  };
}

test('无覆盖配置 → 原样返回 inner（零包装、零开销）', () => {
  const inner = { request: async () => ({ status: 200 }) };
  assert.strictEqual(withScanOverrides(inner, null), inner);
  assert.strictEqual(withScanOverrides(inner, {}), inner);
  assert.strictEqual(withScanOverrides(inner, { requestDelayMs: 0, keepAlive: undefined }), inner);
});

test('requestDelayMs>0 → 注入每次请求的 opts.requestDelayMs', async () => {
  const inner = makeRecorder();
  const wrapped = withScanOverrides(inner, { requestDelayMs: 500 });
  await wrapped.request({ url: 'http://x/', method: 'GET' });
  assert.strictEqual(inner.calls[0].requestDelayMs, 500);
});

test('keepAlive=false 显式关闭 → 注入 opts.keepAlive=false', async () => {
  const inner = makeRecorder();
  const wrapped = withScanOverrides(inner, { keepAlive: false });
  await wrapped.request({ url: 'http://x/', method: 'GET' });
  assert.strictEqual(inner.calls[0].keepAlive, false);
});

test('keepAlive=true（默认值）→ 不额外注入（避免无谓包装），走 HttpClient 内部默认', async () => {
  const inner = makeRecorder();
  const wrapped = withScanOverrides(inner, { keepAlive: true, requestDelayMs: 0 });
  assert.strictEqual(wrapped, inner, '全部为默认值时应零包装');
});

test('请求级显式 opts 优先于扫描级包装值', async () => {
  const inner = makeRecorder();
  const wrapped = withScanOverrides(inner, { requestDelayMs: 500, keepAlive: false });
  await wrapped.request({ url: 'http://x/', method: 'GET', requestDelayMs: 0, keepAlive: true });
  assert.strictEqual(inner.calls[0].requestDelayMs, 0);
  assert.strictEqual(inner.calls[0].keepAlive, true);
});

test('并发隔离：两个扫描各自携带本扫描 delay，互不覆盖（回归：全局单例污染）', async () => {
  const inner = makeRecorder();
  // 模拟两个并发扫描：扫描 A delay=300，扫描 B delay=50
  const wrapA = withScanOverrides(inner, { requestDelayMs: 300 });
  const wrapB = withScanOverrides(inner, { requestDelayMs: 50 });
  // 交错发包（真实并发下请求顺序不定，但每个包装注入的值必须恒为其自身配置）
  await wrapA.request({ url: 'http://a/', method: 'GET' });
  await wrapB.request({ url: 'http://b/', method: 'GET' });
  await wrapB.request({ url: 'http://b2/', method: 'GET' });
  await wrapA.request({ url: 'http://a2/', method: 'GET' });
  const byUrl = Object.fromEntries(inner.calls.map((c) => [c.url, c.requestDelayMs]));
  assert.strictEqual(byUrl['http://a/'], 300);
  assert.strictEqual(byUrl['http://a2/'], 300);
  assert.strictEqual(byUrl['http://b/'], 50);
  assert.strictEqual(byUrl['http://b2/'], 50);
});

test('SafeProbeClient 兼容：包装对象仅需暴露 request 方法（SafeProbeClient 透传依赖）', async () => {
  const inner = makeRecorder();
  const wrapped = withScanOverrides(inner, { requestDelayMs: 100 });
  // SafeProbeClient 只调用 inner.request —— 包装对象没有额外属性不影响其运行
  assert.strictEqual(typeof wrapped.request, 'function');
  const res = await wrapped.request({ url: 'http://x/', method: 'GET' });
  assert.strictEqual(res.status, 200);
});

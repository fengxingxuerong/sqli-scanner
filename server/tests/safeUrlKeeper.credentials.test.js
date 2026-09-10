// ============================================================================
// tests/safeUrlKeeper.credentials.test.js —— 保活请求不得把凭据抄送到第三方主机
// [P0-FIX 2026-09-09]
//
// 实战口径：--safe-url 常指向「另一个系统」（网关健康检查 / LB 心跳页 / 监控端点）。
// 原实现无条件继承 auth（Cookie / Authorization / 自定义头），等于把客户生产系统的凭据
// 自动发给一个我们并不控制的第三方，而且静默无痕 —— 这类事在交付复盘里是事故，不是 bug。
// 正确语义：同源才继承会话（这本来就是 sqlmap --safe-url 的用意），跨源只保留出口路径（proxy）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withSafeUrl } from '../src/core/safeUrlKeeper.js';

function mockClient() {
  const calls = [];
  return {
    calls,
    client: {
      async request(opts) {
        calls.push(opts);
        return { status: 200, data: 'ok', headers: {} };
      },
    },
  };
}

const AUTH = { basic: { username: 'admin', password: 'p@ss' }, cookie: 'sid=SECRET', headers: { 'X-Token': 'T' } };

test('safeUrl 与目标同源：仍继承 auth（会话保活语义不变）', async () => {
  const { calls, client } = mockClient();
  const wrapped = withSafeUrl(client, { safeUrl: 'http://app.test/keep', safeFreq: 1 });
  await wrapped.request({ url: 'http://app.test/item?id=1', auth: AUTH, proxy: 'http://127.0.0.1:8080' });
  const keepalive = calls[0];
  assert.equal(keepalive.url, 'http://app.test/keep');
  assert.ok(keepalive.auth, '同源保活应带 auth，否则会话照样过期');
  assert.deepEqual(keepalive.auth, AUTH);
});

test('safeUrl 跨源：剥掉 auth，保留 proxy（凭据不外送第三方）', async () => {
  const { calls, client } = mockClient();
  const wrapped = withSafeUrl(client, { safeUrl: 'http://gateway.test/health', safeFreq: 1 });
  await wrapped.request({ url: 'http://app.test/item?id=1', auth: AUTH, proxy: 'http://127.0.0.1:8080' });
  const keepalive = calls[0];
  assert.equal(keepalive.auth, undefined, '跨源保活请求不得携带目标站凭据');
  assert.equal(keepalive.proxy, 'http://127.0.0.1:8080', '出口通道仍需一致');
  // 扫描请求本身不受影响（凭据要发给目标）
  const scan = calls[1];
  assert.equal(scan.url, 'http://app.test/item?id=1');
  assert.deepEqual(scan.auth, AUTH);
});

test('端口不同的同源判定按跨源处理（凭据不跟端口漂）', async () => {
  const { calls, client } = mockClient();
  const wrapped = withSafeUrl(client, { safeUrl: 'http://app.test:8443/keep', safeFreq: 1 });
  await wrapped.request({ url: 'http://app.test/item?id=1', auth: AUTH });
  assert.equal(calls[0].auth, undefined);
});

test('safeUrl 非法时不影响扫描请求本身', async () => {
  const { calls, client } = mockClient();
  const wrapped = withSafeUrl(client, { safeUrl: 'not a url', safeFreq: 1 });
  const res = await wrapped.request({ url: 'http://app.test/item?id=1', auth: AUTH });
  assert.equal(res.status, 200);
  assert.deepEqual(calls.map((c) => c.url).filter(Boolean), ['http://app.test/item?id=1']);
});

// [P1 2026-09-09] 统一错误响应头 X-Error-Code（两步走第一步）
// 背景：业务错误全部返回 HTTP 200 + code，监控/网关/代理看不到失败率，curl -f 也拦不住。
// 第一步：所有含数字 code 的 JSON 错误响应自动携带 X-Error-Code 响应头，状态码不变。
// 验证：① 错误响应带 X-Error-Code；② 正常响应（health）不带（不误伤）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../index.js';

async function withApp(fn) {
  const app = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = server.address().port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('错误响应携带 X-Error-Code 头（跨站 Origin 403）', async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
      body: JSON.stringify({ target: { url: 'http://127.0.0.1:1/?id=1' } }),
    });
    assert.equal(res.status, 403);
    assert.equal(res.headers.get('x-error-code'), '403');
  });
});

test('错误响应携带 X-Error-Code 头（非 JSON 请求体 415）', async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: '{"target":{"url":"http://127.0.0.1:1/?id=1"}}',
    });
    assert.equal(res.status, 415);
    assert.equal(res.headers.get('x-error-code'), '415');
  });
});

test('正常响应不带 X-Error-Code（不误伤成功路径）', async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/api/health`);
    assert.ok(res.ok, `health 应 2xx，实际 ${res.status}`);
    assert.equal(res.headers.get('x-error-code'), null);
  });
});
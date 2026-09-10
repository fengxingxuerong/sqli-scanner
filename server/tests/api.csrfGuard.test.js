// ============================================================================
// tests/api.csrfGuard.test.js —— 扫描器自身的跨站驱动防护
// [P0-SEC 2026-09-09]
//
// 实战意义：本服务默认监听 127.0.0.1，**浏览器可以直接打到回环端口**。`cors` 中间件在
// Origin 不在白名单时只是不发 CORS 头，请求仍然进 handler —— 写操作已经执行。于是
// 「让受害者点一下网页，就把他正在扫的目标改掉 / 停掉他的扫描 / 触发一次拖库」是可行的。
// 之前没出事只因为 express.json 不解析非 JSON body，属侥幸。
// ============================================================================

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

const post = (base, path, opts = {}) =>
  fetch(`${base}${path}`, { method: 'POST', ...opts });

test('跨站 Origin 的变更请求：403，且不进入业务逻辑', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
      body: JSON.stringify({ target: { url: 'http://127.0.0.1:1/?id=1' } }),
    });
    assert.equal(res.status, 403, 'Origin 不在白名单必须被拒（不是只缺 CORS 头）');
    const j = await res.json();
    assert.match(String(j.message || ''), /Origin/);
  });
});

test('沙箱 iframe 的 Origin: null 同样被拒', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/json', Origin: 'null' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 403);
  });
});

test('非 JSON 请求体：415（而不是被 express.json 静默丢 body 后报「参数缺失」）', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'text/plain' },
      body: '{"target":{"url":"http://127.0.0.1:1/?id=1"}}',
    });
    assert.equal(res.status, 415);
    const form = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'target=url',
    });
    assert.equal(form.status, 415);
  });
});

test('无 Origin 的命令行/脚本客户端：不被本层拦（交给业务校验）', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    // 本服务统一用 HTTP 200 + code 包裹错误（见下方备注），所以断言不能靠 status 区分成败：
    // 关键是「不得被跨站守卫拒（403/415）」且「必须落到业务校验（code=1003 缺少目标 URL）」。
    assert.ok(res.status !== 403 && res.status !== 415, `curl 类客户端不应被跨站守卫拦，实际 ${res.status}`);
    const j = await res.json();
    assert.equal(j.code, 1003, `应走到参数校验，实际返回 ${JSON.stringify(j)}`);
  });
});

test('同源（Origin == Host）放行：静态托管/Tauri 同 host:port 场景不能被打断', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/json', Origin: base },
      body: JSON.stringify({}),
    });
    assert.ok(res.status !== 403 && res.status !== 415, `同源请求应到业务层，实际 ${res.status}`);
    const j = await res.json();
    assert.equal(j.code, 1003);
  });
});

test('无 Origin 但 Sec-Fetch-Site: cross-site：拒', async () => {
  await withApp(async (base) => {
    const res = await post(base, '/api/scan/start', {
      headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 403);
  });
});

test('只读方法不受影响（GET /health 正常）', async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/health`, { headers: { Origin: 'http://evil.example' } });
    assert.ok(res.status === 200 || res.status === 404, `只读路径不应被跨站守卫拦，实际 ${res.status}`);
  });
});

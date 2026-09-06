// 测试 server/src/api/sqlmapRoutes.js 路由层
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { sqlmapRoutes } from '../src/api/sqlmapRoutes.js';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/sqlmap', sqlmapRoutes);
  return app;
}

async function req(app, method, path, body) {
  const server = app.listen(0);
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json() };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('GET /sqlmap/status 返回 {available, maxConcurrent}（不含 script/python）', async () => {
  const { json } = await req(buildApp(), 'GET', '/sqlmap/status');
  assert.equal(json.code, 0);
  const d = json.data;
  assert.equal(typeof d.available, 'boolean');
  assert.equal(typeof d.maxConcurrent, 'number');
  assert.ok(!('script' in d), '不应返回 script 路径');
  assert.ok(!('python' in d), '不应返回 python 路径');
});

test('POST /sqlmap/start 无 url 时返回错误', async () => {
  const { json } = await req(buildApp(), 'POST', '/sqlmap/start', {});
  assert.notEqual(json.code, 0, '无 url 应返回非零错误码');
  assert.equal(json.data, null);
});

test('GET /sqlmap/:id/report 不存在时返回 SCAN_NOT_FOUND', async () => {
  const { json } = await req(buildApp(), 'GET', '/sqlmap/no-such-id/report');
  assert.equal(json.code, 2001);
  assert.equal(json.data, null);
});

test('POST /sqlmap/:id/stop 不存在时返回 {stopped: false}', async () => {
  const { json } = await req(buildApp(), 'POST', '/sqlmap/no-such-id/stop');
  assert.equal(json.code, 0);
  assert.equal(json.data.stopped, false);
});

// ============================================================================
// tests/rateLimit.test.js —— API 速率限制（全方位优化建议 2026-09-30 §1.2）
//
// 审计验收口径：至少 3 条用例——窗口内允许 / 超限 429 / 不同 token 独立计额。
// 实测缺口是 POST /scan/start（exploit/* 已有 5 req/s 桶、/report/ai 已有每 IP
// 每分钟 3 次内联限速，见 rateLimit.js 头注释的挂载差异说明）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createRateLimiter } from '../src/api/rateLimit.js';
import { ErrorCode } from '../src/core/errors.js';
import { createApp } from '../index.js';

async function withServer(app, fn) {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const call = (base, path, headers = {}) =>
  fetch(`${base}${path}`, { method: 'POST', headers });

test('窗口内允许 max 次；超限返回 429 + RATE_LIMITED + Retry-After/RateLimit-* 头', async () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 3, name: 'unit' });
  const app = express();
  app.post('/x', express.json(), limiter, (_req, res) => res.json({ ok: true }));
  await withServer(app, async (base) => {
    for (let i = 0; i < 3; i++) {
      const res = await call(base, '/x', { 'x-api-token': 'tokA1111-anything' });
      assert.equal(res.status, 200, `第 ${i + 1} 次应放行`);
      assert.equal(res.headers.get('ratelimit-limit'), '3');
      assert.equal(res.headers.get('ratelimit-remaining'), String(2 - i));
    }
    const res = await call(base, '/x', { 'x-api-token': 'tokA1111-anything' });
    assert.equal(res.status, 429);
    assert.equal(res.headers.get('retry-after') !== null, true);
    assert.equal(res.headers.get('ratelimit-remaining'), '0');
    const j = await res.json();
    assert.equal(j.code, ErrorCode.RATE_LIMITED, `429 响应应带 RATE_LIMITED(${ErrorCode.RATE_LIMITED}) 码`);
    assert.match(String(j.message), /unit/);
  });
});

test('不同 token 独立计额（同一窗口内 A 超限不影响 B）', async () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 2, name: 'unit' });
  const app = express();
  app.post('/x', express.json(), limiter, (_req, res) => res.json({ ok: true }));
  await withServer(app, async (base) => {
    for (let i = 0; i < 2; i++) {
      assert.equal((await call(base, '/x', { 'x-api-token': 'tokC2222-x' })).status, 200);
    }
    assert.equal((await call(base, '/x', { 'x-api-token': 'tokC2222-x' })).status, 429, 'A 超限');
    assert.equal((await call(base, '/x', { 'x-api-token': 'tokD3333-y' })).status, 200, 'B 独立计额');
  });
});

test('窗口翻新后配额重置；OPTIONS 预检不计额；max<=0 为直通', async () => {
  const limiter = createRateLimiter({ windowMs: 120, max: 1, name: 'unit' });
  const app = express();
  app.all('/x', express.json(), limiter, (_req, res) => res.json({ ok: true }));
  await withServer(app, async (base) => {
    assert.equal((await call(base, '/x', { 'x-api-token': 'tokE4444' })).status, 200);
    assert.equal((await call(base, '/x', { 'x-api-token': 'tokE4444' })).status, 429);
    assert.equal(
      (await fetch(`${base}/x`, { method: 'OPTIONS' })).status,
      200,
      'OPTIONS 预检不消耗配额也不被 429'
    );
    await new Promise((r) => setTimeout(r, 140));
    assert.equal((await call(base, '/x', { 'x-api-token': 'tokE4444' })).status, 200, '新窗口重置');
  });

  const off = createRateLimiter({ windowMs: 60_000, max: 0, name: 'off' });
  const app2 = express();
  app2.post('/x', off, (_req, res) => res.json({ ok: true }));
  await withServer(app2, async (base) => {
    for (let i = 0; i < 5; i++) {
      assert.equal((await call(base, '/x')).status, 200, 'max<=0 应直通（限流关闭）');
    }
  });
});

test('接线验收：真实 app 上同一 token 第 11 次 POST /api/scan/start 得 429，其他 token 不受影响', async () => {
  const app = createApp();
  const tokenA = `rlitA${Date.now() % 100000}`.slice(0, 16);
  const tokenB = `rlitB${Date.now() % 100000}`.slice(0, 16);
  await withServer(app, async (base) => {
    let sawLimit = false;
    for (let i = 0; i < 11; i++) {
      const res = await fetch(`${base}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-token': tokenA },
        body: JSON.stringify({ target: { url: 'http://127.0.0.1:1/?id=1' } }),
      });
      if (res.status === 429) {
        sawLimit = true;
        const j = await res.json();
        assert.equal(j.code, ErrorCode.RATE_LIMITED, 'scan/start 超限应带 RATE_LIMITED 码');
        break;
      }
    }
    assert.equal(sawLimit, true, '默认 10 次/分钟：第 11 次应触发 429');
    const resB = await fetch(`${base}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-token': tokenB },
      body: JSON.stringify({ target: { url: 'http://127.0.0.1:1/?id=1' } }),
    });
    assert.notEqual(resB.status, 429, 'token B 独立计额，不应被 A 的超限连坐');
  });
});

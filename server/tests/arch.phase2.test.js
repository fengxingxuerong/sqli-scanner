// 架构/安全 Phase 2 回归测试（子代理 C 收尾补测）
// 覆盖：日志脱敏 redact/redactHeaders、报告访问护栏（createReportGuard / createRoutes 注入）、
//       createRoutes 工厂可注入、createApp 全局 token 护栏。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { redact, redactHeaders, truncateLong } from '../src/core/logger.js';
import { createRoutes } from '../src/api/scanRoutes.js';
import { createApp } from '../index.js';

// ── 发请求到临时 app（listen 随机端口，用完即关）─────────────────
function request(app, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          server.close();
          let parsed = null;
          try {
            parsed = JSON.parse(body || '{}');
          } catch {
            parsed = body;
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      });
      req.on('error', (e) => {
        server.close();
        reject(e);
      });
      req.end();
    });
  });
}

// ── redact 脱敏 ─────────────────────────────────────────────
test('redact：剥离 URL 内嵌凭据 user:pass@', () => {
  const out = redact('GET https://admin:secret123@example.com/api');
  assert.ok(!out.includes('secret123'));
  assert.ok(!out.includes('admin:'));
  assert.ok(out.includes('***:***@'));
  assert.ok(out.includes('example.com'));
});

test('redact：打码 Authorization Bearer 头值', () => {
  const out = redact('Authorization: Bearer eyJhbGciOi.xxx.yyy');
  assert.ok(!out.includes('eyJhbGciOi'));
  assert.ok(out.includes('***'));
});

test('redact：打码 Cookie 头值', () => {
  const out = redact('Cookie: sessionid=abcdef123456; other=1');
  assert.ok(!out.includes('abcdef123456'));
});

test('redact：打码通用敏感键值 + 超长截断', () => {
  const out = redact('password=hunter2 token=abc', { maxLength: 8 });
  assert.ok(!out.includes('hunter2'));
  assert.ok(!out.includes('abc'));
  assert.ok(out.includes('[截断'));
  assert.ok(out.length <= 20);
});

test('redactHeaders：敏感头值整体替换为 ***，非敏感头保留', () => {
  const out = redactHeaders({
    Authorization: 'Bearer xyz',
    Cookie: 'sid=1',
    'Content-Type': 'application/json',
    'X-Custom': 'keep',
  });
  assert.equal(out.Authorization, '***');
  assert.equal(out.Cookie, '***');
  assert.equal(out['Content-Type'], 'application/json');
  assert.equal(out['X-Custom'], 'keep');
});

test('truncateLong：超长截断 + 打标，短值原样返回', () => {
  assert.equal(truncateLong('short', 100), 'short');
  const out = truncateLong('x'.repeat(50), 10);
  assert.ok(out.includes('[截断 40 字符]'));
});

// ── 报告访问护栏（createRoutes 注入）────────────────────────
test('createRoutes：reportToken 注入后，报告端点无凭据返回 401', async () => {
  const app = express();
  app.use(express.json());
  app.use('/', createRoutes({ reportToken: 'secret-token' }));
  const res = await request(app, 'GET', '/scan/whatever/report');
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 401);
});

test('createRoutes：携带正确 X-Scan-Token 放行（非 401）', async () => {
  const app = express();
  app.use(express.json());
  app.use('/', createRoutes({ reportToken: 'secret-token' }));
  const res = await request(app, 'GET', '/scan/whatever/report', {
    'X-Scan-Token': 'secret-token',
  });
  assert.notEqual(res.status, 401);
});

test('createRoutes：Authorization: Bearer 形式放行', async () => {
  const app = express();
  app.use(express.json());
  app.use('/', createRoutes({ reportToken: 'secret-token' }));
  const res = await request(app, 'GET', '/scan/whatever/report', {
    Authorization: 'Bearer secret-token',
  });
  assert.notEqual(res.status, 401);
});

test('createRoutes：未设 token 时报告端点放行（本地单机零成本）', async () => {
  const app = express();
  app.use(express.json());
  app.use('/', createRoutes({}));
  const res = await request(app, 'GET', '/scan/whatever/report');
  assert.notEqual(res.status, 401);
});

test('createRoutes：报告导出端点同样受护栏保护', async () => {
  const app = express();
  app.use(express.json());
  app.use('/', createRoutes({ reportToken: 'secret-token' }));
  const res = await request(app, 'GET', '/scan/whatever/report/export?format=json');
  assert.equal(res.status, 401);
});

// ── createApp 全局 token 护栏 ───────────────────────────────
test('createApp：设置 SCAN_API_TOKEN 后，报告端点无凭据 401', async () => {
  const old = process.env.SCAN_API_TOKEN;
  process.env.SCAN_API_TOKEN = 'global-secret';
  try {
    const app = createApp();
    const res = await request(app, 'GET', '/api/scan/whatever/report');
    assert.equal(res.status, 401);
  } finally {
    process.env.SCAN_API_TOKEN = old;
  }
});

test('createApp：健康检查为公开只读，不要求 token', async () => {
  const old = process.env.SCAN_API_TOKEN;
  process.env.SCAN_API_TOKEN = 'global-secret';
  try {
    const app = createApp();
    const res = await request(app, 'GET', '/api/health');
    assert.notEqual(res.status, 401);
  } finally {
    process.env.SCAN_API_TOKEN = old;
  }
});

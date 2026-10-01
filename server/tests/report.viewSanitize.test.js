// ============================================================================
// tests/report.viewSanitize.test.js —— 「查看」与「导出」脱敏同源（2026-10-01）
// ============================================================================
// 缺陷（审计实证）：GET /scan/:id 与 /scan/:id/report 返回**未脱敏**原 report，
// 而 /scan/:id/report/export 早就经 sanitizeTargetForExport 打码 ⇒ 同一份报告两条
// 口径，更松的那条恰是前端每次打开报告都调的。同时导出脱敏漏了 db.password
// （分项直连配置的口令原文外发）。
// 钉法：
//   ① 纯函数层：sanitizeForView 掩 auth/proxy/db.connectionString/db.password，
//      **不掩** cookieParams/headerParams（前端 PoC 渲染需要，且 poc 字段含同值）；
//   ② 导出口径：db.password 同步打码（sanitizeTargetForExport 经 exportReport JSON 体现）；
//   ③ HTTP 层：/scan/:id 与 /scan/:id/report 响应里上述字段已打码。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { createRoutes } from '../src/api/scanRoutes.js';

const SECRET_REPORT = {
  scanId: 's1',
  target: {
    baseUrl: 'http://shop.example.com/item?id=1',
    method: 'GET',
    cookieParams: { SESSION: 'sess-cookie-value' },
    headerParams: { 'X-Custom': 'v' },
    config: {
      auth: { basic: { username: 'admin', password: 's3cret' } },
      proxy: 'http://user:pass@proxy.local:8080',
      dbms: 'MySQL',
    },
    db: { host: '10.0.0.8', user: 'root', password: 'db-s3cret', connectionString: 'mysql://root:db-s3cret@10.0.0.8/shop' },
  },
  vulnerabilities: [],
  summary: {},
};

const rg = new ReportGenerator();

test('sanitizeForView：auth/proxy/db.* 打码，cookieParams/headerParams 保留', () => {
  const out = rg.sanitizeForView(SECRET_REPORT);
  assert.equal(out.target.config.auth, null, 'auth 凭据不得随查看接口外发');
  assert.equal(out.target.config.proxy, null, 'proxy（可含口令）不得随查看接口外发');
  assert.equal(out.target.db.password, '***', 'db.password 必须打码');
  assert.equal(out.target.db.connectionString, '***', 'db.connectionString 必须打码');
  assert.equal(out.target.config.dbms, 'MySQL', '非敏感配置原样保留');
  assert.deepEqual(out.target.cookieParams, { SESSION: 'sess-cookie-value' }, 'cookieParams 保留（PoC 渲染需要）');
  assert.deepEqual(out.target.headerParams, { 'X-Custom': 'v' }, 'headerParams 保留（PoC 渲染需要）');
  // 不写回原对象
  assert.equal(SECRET_REPORT.target.config.auth.basic.password, 's3cret', '原 report 不得被污染');
});

test('导出口径：db.password 与 connectionString 同口径打码', () => {
  const parsed = JSON.parse(rg.toJSON(SECRET_REPORT));
  assert.equal(parsed.target.db.password, '***', '导出漏掩 db.password（修复前原文外发）');
  assert.equal(parsed.target.db.connectionString, '***');
  assert.equal(parsed.target.config.auth, null);
});

// ── HTTP 层：两个查看端点都走同一口径 ─────────────────────────────────────
const stubManager = {
  getReport: (id) => (id === 's1' ? SECRET_REPORT : null),
  status: () => ({ status: 'completed', paused: false }),
  reportGen: rg,
};

async function withApp(fn) {
  const app = express();
  app.use('/api', createRoutes({ scanManager: stubManager }));
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

test('GET /scan/:id 与 /scan/:id/report：响应已按查看口径脱敏', async () => {
  await withApp(async (base) => {
    for (const path of ['/api/scan/s1', '/api/scan/s1/report']) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 200, `${path} 应 200`);
      const body = await res.json();
      const t = body.data.target;
      assert.equal(t.config.auth, null, `${path} 外发 auth 原文`);
      assert.equal(t.config.proxy, null, `${path} 外发 proxy 原文`);
      assert.equal(t.db.password, '***', `${path} 外发 db.password 原文`);
      assert.equal(t.db.connectionString, '***', `${path} 外发 connectionString 原文`);
      assert.equal(t.cookieParams.SESSION, 'sess-cookie-value', `${path} 不应掩 cookieParams（PoC 渲染需要）`);
    }
  });
});

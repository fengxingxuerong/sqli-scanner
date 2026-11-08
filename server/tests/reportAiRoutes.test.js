// reportAiRoutes 零覆盖补测：configs 端点 / 404 映射 / 限速护栏 / 生成成功路径
// 注意：AI 限速为每 IP 每分钟 3 次的模块级状态，本文件 POST 用例恰好 3 个，顺序不可增删。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

// [P2-FIX 2026-09-05] AI 报告外发 opt-in：必须显式设置 AI_REPORT_API_BASE 才启用外发。
// 该测试打桩全局 fetch（不发真实网络请求），故设 AI_REPORT_API_BASE 指向本地假端点以通过启用预检。
process.env.AI_REPORT_API_BASE = 'http://127.0.0.1:9/v1/chat/completions';
process.env.AI_REPORT_KEY_1 = 'rt-key-1';
const { createApp } = await import('../index.js');
const { defaultScanManager } = await import('../src/api/scanRoutes.js');

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
          try { parsed = JSON.parse(body || '{}'); } catch { parsed = body; }
          resolve({ status: res.statusCode, body: parsed });
        });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      req.end();
    });
  });
}

test('GET /api/scan/:id/report/ai/configs：返回 3 角色配置', async () => {
  const app = createApp();
  const res = await request(app, 'GET', '/api/scan/whatever/report/ai/configs');
  assert.equal(res.status, 200);
  assert.equal(res.body.code, 0);
  assert.equal(res.body.data.length, 3);
});

test('[D275] GET /api/scan/:id/report/ai/limits：默认 600s/600s/120s，env 覆盖生效', async () => {
  const app = createApp();
  const res = await request(app, 'GET', '/api/scan/whatever/report/ai/limits');
  assert.equal(res.status, 200);
  assert.equal(res.body.code, 0);
  assert.deepEqual(res.body.data, {
    requestTimeoutMs: 600000,
    totalTimeoutMs: 600000,
    stepwiseTimeoutMs: 120000,
    stepwiseConcurrency: 1,
  });
  process.env.AI_REPORT_TIMEOUT_MS = '12345';
  try {
    const res2 = await request(app, 'GET', '/api/scan/whatever/report/ai/limits');
    assert.equal(res2.body.data.requestTimeoutMs, 12345);
  } finally {
    delete process.env.AI_REPORT_TIMEOUT_MS;
  }
});

test('POST AI 报告：扫描不存在 → 404（原误映射 500，已修）', async () => {
  const app = createApp();
  const res = await request(app, 'POST', '/api/scan/no-such-scan/report/ai');
  assert.equal(res.status, 404);
  assert.ok(String(res.body.message).includes('扫描任务不存在'));
});

test('POST AI 报告：报告未生成 → 404', async () => {
  defaultScanManager.scans.set('rt-no-report', { id: 'rt-no-report', report: null });
  try {
    const app = createApp();
    const res = await request(app, 'POST', '/api/scan/rt-no-report/report/ai');
    assert.equal(res.status, 404);
    assert.ok(String(res.body.message).includes('扫描报告尚未生成'));
  } finally {
    defaultScanManager.scans.delete('rt-no-report');
  }
});

test('POST AI 报告成功：fetch 打桩 → code 0 返回流水线结果', async () => {
  defaultScanManager.scans.set('rt-ok', {
    id: 'rt-ok',
    report: {
      scanId: 'rt-ok',
      target: { baseUrl: 'https://example.com/pw' },
      dbms: 'MySQL',
      vulns: [{ technique: 'error', dbms: 'MySQL', riskLevel: 'High' }],
    },
  });
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    json: async () => ({ choices: [{ message: { content: '# AI 报告' } }] }),
  });
  try {
    const app = createApp();
    const res = await request(app, 'POST', '/api/scan/rt-ok/report/ai');
    assert.equal(res.status, 200);
    assert.equal(res.body.code, 0);
    assert.equal(res.body.data.success, true);
    assert.ok(res.body.data.content.startsWith('# AI 报告'), '模型正文保留');
    assert.ok(res.body.data.content.includes('<!-- engine-boundary -->'), '[D275] 确定性边界章节必须随报告返回');
    assert.equal(res.body.data.boundary.verdict, null, '报告无 verdict 时不得兜底成「未检出」');
  } finally {
    globalThis.fetch = origFetch;
    defaultScanManager.scans.delete('rt-ok');
  }
});

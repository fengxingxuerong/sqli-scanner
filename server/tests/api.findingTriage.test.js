// ============================================================================
// api.findingTriage.test.js —— [D125 2026-10-22] 人工裁决 REST 契约
//
// 真接口（express + createRoutes）+ 桩 ScanManager（不跑扫描）：
//   PATCH /api/scan/:id/findings/:findingId/triage → 写入并按指纹持久化
//   GET   /api/scan/:id/report                    → 报告读取时合并裁决
//   GET   /api/scan/:id/report/export             → 导出与查看同源（此前导出绕过 triage）
// 同时钉住失败形态：未知状态 / 未知 finding / 未知字段都必须明确 4xx，不得静默 200。
// ============================================================================
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';
import { createRoutes } from '../src/api/scanRoutes.js';
import { createInjectionPoint, createVulnerability } from '../src/engine/models.js';
import { attachVulnContext } from '../src/engine/vulnEnrich.js';
import { listenAppSafe } from './support/listenSafe.js';

const DIR = mkdtempSync(join(tmpdir(), 'sqli-triage-api-'));
process.env.SQLI_TRIAGE_FILE = join(DIR, 'triage.json');
process.env.SQLI_LEDGER_DIR = join(DIR, 'ledger'); // 隔离 readReport 兜底，避免读到本机真实台账
after(() => rmSync(DIR, { recursive: true, force: true }));

const ITEM_URL = 'http://shop.example.com/item?id=1';

function makeReport() {
  const point = createInjectionPoint('url', 'id', '1', { actionUrl: ITEM_URL });
  const vuln = Object.assign(
    createVulnerability(point.id, 'boolean', 'High', ['1 AND 1=1'], '真/假响应差异'),
    { dbms: 'MySQL' }
  );
  return attachVulnContext({
    scanId: 's1',
    target: { mode: 'http', method: 'GET', baseUrl: ITEM_URL },
    points: [point],
    vulns: [vuln],
    data: {},
    summary: { verdict: 'vulnerability_detected' },
  });
}

/** 固定一份基准报告：每次 getReport 返回其副本（id 稳定，贴近真实扫描的 structuredClone）。 */
const BASE_REPORT = makeReport();

/** 只实现本测试需要的两个方法。 */
const stubManager = {
  getReport: (id) => (id === 's1' ? structuredClone(BASE_REPORT) : null),
  exportReport: (id, format, reportArg) => (reportArg ? JSON.stringify(reportArg) : null),
};

async function withApp(fn) {
  const app = express();
  app.use(express.json());
  app.use('/api', createRoutes({ scanManager: stubManager }));
  const server = await listenAppSafe(app);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const json = async (res) => ({ status: res.status, body: await res.json() });

test('PATCH 写入裁决 → GET 报告与导出都带 triage/summary', async () => {
  await withApp(async (base) => {
    const vulnId = BASE_REPORT.vulns[0].id;
    const patched = await json(
      await fetch(`${base}/api/scan/s1/findings/${encodeURIComponent(vulnId)}/triage`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ status: 'confirmed', note: '已手工复现' }),
      })
    );
    assert.equal(patched.status, 200);
    assert.equal(patched.body.code, 0);
    assert.equal(patched.body.data.triage.status, 'confirmed');
    assert.match(patched.body.data.findingKey, /^GET .*\|url\|id\|boolean$/);

    const got = await json(await fetch(`${base}/api/scan/s1/report`));
    assert.equal(got.status, 200);
    assert.equal(got.body.data.vulns[0].triage.status, 'confirmed');
    assert.equal(got.body.data.vulns[0].triage.note, '已手工复现');
    assert.deepEqual(got.body.data.summary.triage, { total: 1, open: 0, confirmed: 1, falsePositive: 0, acceptedRisk: 0 });

    const exported = await json(await fetch(`${base}/api/scan/s1/report/export?format=json`));
    assert.equal(exported.status, 200);
    assert.equal(exported.body.vulns[0].triage.status, 'confirmed', '导出必须与查看同源（D125 前它绕过了 triage）');
    assert.equal(exported.body.summary.triage.confirmed, 1);
  });
});

test('PATCH 支持用稳定 findingKey 更新（复扫后仍可用）', async () => {
  await withApp(async (base) => {
    const key = (await json(await fetch(`${base}/api/scan/s1/report`))).body.data.vulns[0].findingKey;
    const res = await json(
      await fetch(`${base}/api/scan/s1/findings/${encodeURIComponent(key)}/triage`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ status: 'accepted_risk', note: '客户接受' }),
      })
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.data.triage.status, 'accepted_risk');
  });
});

test('失败形态：非法状态 / 未知 finding / 未知字段 / 不存在的扫描都必须明确 4xx', async () => {
  await withApp(async (base) => {
    const vulnId = BASE_REPORT.vulns[0].id;
    const patch = (path, body) =>
      fetch(`${base}${path}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });

    const badStatus = await json(await patch(`/api/scan/s1/findings/${vulnId}/triage`, { status: 'nope' }));
    assert.equal(badStatus.status, 400);
    assert.match(badStatus.body.message, /无效的裁决状态/);

    const unknownFinding = await json(await patch('/api/scan/s1/findings/missing/triage', { status: 'confirmed' }));
    assert.equal(unknownFinding.status, 404);
    assert.match(unknownFinding.body.message, /未找到该漏洞/);

    const unknownField = await json(await patch(`/api/scan/s1/findings/${vulnId}/triage`, { status: 'confirmed', extra: 1 }));
    assert.equal(unknownField.status, 400);
    assert.match(unknownField.body.message, /未知字段/);

    const missingScan = await json(await patch('/api/scan/gone/findings/x/triage', { status: 'confirmed' }));
    assert.equal(missingScan.status, 404);
    assert.match(missingScan.body.message, /扫描不存在/);
  });
});

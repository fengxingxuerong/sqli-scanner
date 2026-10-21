// [D121 2026-10-21] GraphQL 内联点的端到端回归：本地 GraphQL 靶场 + 真 ScanManager。
//
// 判据不是「构造出的字符串长得对」，而是**真扫描能检出**：
//   filter 值含 `1=1` → 两行；含 `1=2` → 空；基线 `x` → 空。
// 这是 DVGA `resolve_pastes` 的最小同构模型（SQL 拼接发生在 resolver 内）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ScanManager } from '../src/engine/ScanManager.js';

process.env.SSRF_ALLOW_PRIVATE = '1';

const QUERY = '{ pastes(public: true, filter: "x") { id title } }';

// 从 GraphQL JSON body 里取 filter 字面量（JSON 解码后的值）。
function filterValue(rawBody) {
  let query = '';
  try {
    query = JSON.parse(rawBody).query || '';
  } catch {
    return '';
  }
  const m = query.match(/filter:\s*"((?:[^"\\]|\\.)*)"/);
  if (!m) return '';
  try {
    return JSON.parse(`"${m[1]}"`);
  } catch {
    return '';
  }
}

function startLab({ vulnerable = true } = {}) {
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const val = filterValue(raw).replace(/[\s'"]/g, '');
      const rows = !vulnerable
        ? []
        : val.includes('1=2')
          ? []
          : val.includes('1=1')
            ? [{ id: 1, title: 'alpha' }, { id: 2, title: 'beta' }, { id: 3, title: 'gamma' }]
            : [];
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: { pastes: rows } }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function waitDone(sm, id, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('scan timeout');
}

test('D121-⑬: 真 ScanManager 对 GraphQL 内联 filter 检出布尔盲注（DVGA 同构）', async () => {
  const lab = await startLab();
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/graphql`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      jsonBody: { query: QUERY },
      config: {
        techniques: ['boolean'],
        level: 1,
        risk: 1,
        concurrency: 1,
        ratePerSec: 400,
        prefilter: false,
        skipStatic: false,
        smart: false,
      },
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const report = sm.getReport(id);
    const hit = report.vulns.find((v) => v.technique === 'boolean');
    assert.ok(hit, `应检出 boolean，实际 vulns=${JSON.stringify(report.vulns)}`);
    assert.equal(hit.param, 'query.filter');
    assert.ok(hit.payloads.length > 0, '应记录命中的 payload');
  } finally {
    lab.close();
  }
});

test('D121-⑭: 同一 GraphQL 端点无注入时零误报（filter 原样返回空）', async () => {
  const lab = await startLab({ vulnerable: false });
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/graphql`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      jsonBody: { query: '{ pastes(public: true, filter: "x") { id title } }' },
      config: {
        techniques: ['boolean'],
        level: 1,
        risk: 1,
        concurrency: 1,
        ratePerSec: 400,
        prefilter: false,
        skipStatic: false,
        smart: false,
      },
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const report = sm.getReport(id);
    assert.equal(report.vulns.length, 0, `不应有命中：${JSON.stringify(report.vulns)}`);
  } finally {
    lab.close();
  }
});

// [D45 2026-10-11] diff-aware CI 门禁单测：基线解析 / 退出码裁决 / 台账集成（临时目录隔离）。
// diff 计算本体（scanDiff.js）由既有 REST 契约覆盖；这里钉的是 CI 门禁层的裁决语义。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  normalizeTarget,
  findBaselineScanId,
  resolveBaselineReport,
  decideDiffExit,
} from '../src/services/diffGate.js';

// ===== normalizeTarget =====
test('normalizeTarget：去 hash、同 URL 归一、非 URL 去 query', () => {
  assert.equal(normalizeTarget('http://t.example.com/a?id=1#frag'), 'http://t.example.com/a?id=1');
  assert.equal(normalizeTarget('t.example.com/a?x=1'), 't.example.com/a');
  assert.equal(normalizeTarget('-'), '');
  assert.equal(normalizeTarget(undefined), '');
});

// ===== findBaselineScanId =====
const rows = [
  { scanId: 'newest', target: 'http://t.example.com/a?id=1' },
  { scanId: 'mid', target: 'http://t.example.com/a?id=1' },
  { scanId: 'other', target: 'http://other.example.com/b?id=1' },
  { scanId: 'oldest', target: 'http://t.example.com/a?id=1' },
];

test('findBaselineScanId：auto 按目标取最近且排除本次自身', () => {
  const id = findBaselineScanId({
    diffBase: 'auto', currentScanId: 'current', currentTarget: 'http://t.example.com/a?id=1', rows,
  });
  assert.equal(id, 'newest'); // rows 新→旧，第一个同目标且非自身
});

test('findBaselineScanId：显式 scanId 命中；自己是基线 → null；不存在 → null', () => {
  assert.equal(
    findBaselineScanId({ diffBase: 'oldest', currentScanId: 'current', currentTarget: '', rows }),
    'oldest'
  );
  assert.equal(findBaselineScanId({ diffBase: 'current', currentScanId: 'current', currentTarget: '', rows }), null);
  assert.equal(findBaselineScanId({ diffBase: 'ghost', currentScanId: 'current', currentTarget: '', rows }), null);
  assert.equal(findBaselineScanId({ diffBase: '', currentScanId: 'current', currentTarget: '', rows }), null);
});

// ===== decideDiffExit =====
const mkDiff = (added, remaining, baseCount) => ({
  new: added,
  remaining,
  base: { vulnCount: baseCount },
});
const mkReport = (reliable = true) => ({
  summary: { validity: { reliable, status: reliable ? 'ok' : 'blocked' } },
});

test('decideDiffExit：新增 → exit 2 并列出新增点位', () => {
  const d = decideDiffExit({
    diff: mkDiff([{ location: 'url', param: 'q', technique: 'error' }], [{ location: 'url', param: 'id', technique: 'error' }], 1),
    newReport: mkReport(),
  });
  assert.equal(d.code, 2);
  assert.ok(d.reason.includes('url:q:error'));
});

test('decideDiffExit：仅存量仍在 → exit 0（不阻塞无关 PR）', () => {
  const d = decideDiffExit({
    diff: mkDiff([], [{ location: 'url', param: 'id', technique: 'error' }], 1),
    newReport: mkReport(),
  });
  assert.equal(d.code, 0);
  assert.ok(d.reason.includes('仍存在 1 条'));
});

test('decideDiffExit：本次结论不可信 → exit 1（不判红也不假绿）', () => {
  const d = decideDiffExit({ diff: mkDiff([], [], 0), newReport: mkReport(false) });
  assert.equal(d.code, 1);
  assert.equal(d.gateable, false);
  assert.ok(d.reason.includes('不可信'));
});

test('decideDiffExit：diff 缺形（无 new 数组）→ 保守 exit 0 但不含新增声明', () => {
  const d = decideDiffExit({ diff: { new: null, remaining: [], base: { vulnCount: 0 } }, newReport: mkReport() });
  assert.equal(d.code, 0);
});

// ===== 台账集成（临时目录隔离：SQLI_LEDGER_DIR 每次 test 内设置）=====
function withLedgerDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-diffgate-'));
  const prev = process.env.SQLI_LEDGER_DIR;
  process.env.SQLI_LEDGER_DIR = dir;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (prev === undefined) delete process.env.SQLI_LEDGER_DIR;
      else process.env.SQLI_LEDGER_DIR = prev;
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    });
}

const mkScanReport = (scanId, url, vulnKeys) => ({
  scanId,
  target: { url, baseUrl: url, method: 'GET' },
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  riskLevel: vulnKeys.length ? 'High' : 'Low',
  points: vulnKeys.map((k, i) => ({ id: `p${i}`, location: 'url', param: k })),
  vulns: vulnKeys.map((k, i) => ({
    id: `v${i}`, pointId: `p${i}`, technique: 'error', riskLevel: 'High',
    description: 'x', payloads: ["1'"], location: 'url', param: k,
  })),
  summary: { verdict: vulnKeys.length ? 'vulnerability_found' : 'no_vulnerability_detected', validity: { reliable: true, status: 'ok' } },
});

test('台账集成：同目标两次扫描 → auto 基线 → 无新增 exit 0；新参数注入 → exit 2', () =>
  withLedgerDir(async () => {
    const { recordScan } = await import('../src/services/scanLedger.js');
    const { diffReports } = await import('../src/engine/scanDiff.js');
    const url = 'http://t.example.com/item?id=1';
    // 基线：id 有洞
    recordScan(mkScanReport('base01', url, ['id']));
    // 复扫（同目标同发现）
    recordScan(mkScanReport('again1', url, ['id']));
    const rows1 = (await import('../src/services/diffGate.js')).recentScanRows(100);
    const base1 = findBaselineScanId({ diffBase: 'auto', currentScanId: 'again1', currentTarget: url, rows: rows1 });
    assert.equal(base1, 'base01');
    const baseRep1 = resolveBaselineReport({ baseScanId: base1, scanManager: null });
    assert.ok(baseRep1, '基线报告应从台账读回');
    const d1 = decideDiffExit({ diff: diffReports(baseRep1, mkScanReport('again1', url, ['id'])), newReport: mkScanReport('again1', url, ['id']) });
    assert.equal(d1.code, 0);

    // 第三次：目标多了 q 参数注入（新增发现）
    recordScan(mkScanReport('again2', url, ['id', 'q']));
    const rows2 = (await import('../src/services/diffGate.js')).recentScanRows(100);
    const base2 = findBaselineScanId({ diffBase: 'auto', currentScanId: 'again2', currentTarget: url, rows: rows2 });
    assert.equal(base2, 'again1');
    const d2 = decideDiffExit({
      diff: diffReports(resolveBaselineReport({ baseScanId: base2, scanManager: null }), mkScanReport('again2', url, ['id', 'q'])),
      newReport: mkScanReport('again2', url, ['id', 'q']),
    });
    assert.equal(d2.code, 2);
    assert.ok(d2.reason.includes('url:q:error'));
  }));

test('台账集成：不同目标 → auto 找不到基线（调用方应 exit 1 拒绝认证）', () =>
  withLedgerDir(async () => {
    const { recordScan } = await import('../src/services/scanLedger.js');
    recordScan(mkScanReport('t1x', 'http://a.example.com/x?id=1', ['id']));
    const rows = (await import('../src/services/diffGate.js')).recentScanRows(100);
    const id = findBaselineScanId({
      diffBase: 'auto', currentScanId: 'cur', currentTarget: 'http://b.example.com/y?id=1', rows,
    });
    assert.equal(id, null);
  }));

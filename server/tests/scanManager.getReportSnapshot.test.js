// [P1-PERF 2026-11-02] getReport 终态快照缓存：同一版本只 clone 一次，
// 且缓存是深冻结的只读视图（调用方需要写时必须显式 mutable:true）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';

function seed(sm, status = 'completed') {
  const scanId = 'snap-1';
  sm.scans.set(scanId, {
    status,
    report: {
      scanId,
      finishedAt: '2026-11-02T00:00:00.000Z',
      points: [{ id: 'p1' }],
      vulns: [{ id: 'v1', pointId: 'p1' }],
      summary: { verdict: 'no_vulnerability_detected' },
    },
  });
  return scanId;
}

test('终态报告：两次读取返回同一快照对象（命中缓存）', () => {
  const sm = new ScanManager();
  const id = seed(sm);
  const a = sm.getReport(id);
  const b = sm.getReport(id);
  assert.equal(a, b);
  assert.equal(Object.isFrozen(a), true);
  assert.equal(Object.isFrozen(a.summary), true);
});

test('终态报告：mutable:true 返回可写克隆，不污染缓存', () => {
  const sm = new ScanManager();
  const id = seed(sm);
  const cached = sm.getReport(id);
  const mutable = sm.getReport(id, { mutable: true });
  assert.notEqual(mutable, cached);
  mutable.vulns.push({ id: 'v2' });
  assert.equal(sm.getReport(id).vulns.length, 1, '缓存不应被 mutable 副本的改动污染');
});

test('运行中报告：不冻结、每次返回新对象（避免过期视图）', () => {
  const sm = new ScanManager();
  const id = seed(sm, 'running');
  const a = sm.getReport(id);
  const b = sm.getReport(id);
  assert.notEqual(a, b);
  assert.equal(Object.isFrozen(a), false);
});

test('版本变化（finishedAt/status）会失效旧快照', () => {
  const sm = new ScanManager();
  const id = seed(sm);
  const a = sm.getReport(id);
  sm.scans.get(id).report.finishedAt = '2026-11-02T00:00:01.000Z';
  const b = sm.getReport(id);
  assert.notEqual(a, b);
});

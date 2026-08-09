// ReportGenerator F-19 增量：stacked → Critical 置顶 + byTechnique 统计
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

const mk = (technique, riskLevel = 'Medium') => ({
  pointId: 'p',
  technique,
  dbms: 'MySQL',
  riskLevel,
  payloads: [],
  description: '',
});

test('riskOf: 含 stacked 漏洞 → Critical（置顶，高于 union/error）', () => {
  assert.equal(rg.riskOf([mk('stacked')]), 'Critical');
  // 与 High 级技术同现，仍 Critical
  assert.equal(rg.riskOf([mk('stacked'), mk('union')]), 'Critical');
  assert.equal(rg.riskOf([mk('error'), mk('stacked')]), 'Critical');
});

test('riskOf: 仅 union/error → High（未受 stacked 分支干扰）', () => {
  assert.equal(rg.riskOf([mk('union')]), 'High');
  assert.equal(rg.riskOf([mk('error')]), 'High');
});

test('riskOf: 仅 boolean/time → Medium', () => {
  assert.equal(rg.riskOf([mk('boolean')]), 'Medium');
  assert.equal(rg.riskOf([mk('time')]), 'Medium');
});

test('riskOf: 不影响既有组合定级', () => {
  assert.equal(rg.riskOf([mk('boolean'), mk('union')]), 'High');
});

test('build: byTechnique 含 stacked 计数', () => {
  const report = rg.build(
    's1',
    { baseUrl: 'http://x' },
    [{ id: 'p1' }],
    [mk('stacked', 'Critical'), mk('union', 'High')],
    null
  );
  assert.equal(report.summary.byTechnique.stacked, 1);
  assert.equal(report.summary.byTechnique.union, 1);
  assert.equal(report.riskLevel, 'Critical');
});

test('build: 去重后 SQL Server time+stacked 场景，仅计 stacked', () => {
  // 模拟聚合后只保留 1 条 stacked
  const report = rg.build(
    's2',
    { baseUrl: 'http://x' },
    [{ id: 'p1' }],
    [mk('stacked', 'Critical')],
    null
  );
  assert.equal(report.summary.byTechnique.stacked, 1);
  assert.equal(report.summary.byTechnique.time, undefined);
  assert.equal(report.riskLevel, 'Critical');
});

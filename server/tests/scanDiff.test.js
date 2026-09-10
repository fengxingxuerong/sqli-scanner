// 两次扫描差异对比（scanDiff）单测
// 交付场景：修完漏洞要能证明「确实修好了」—— 该接口的输出会直接进客户报告，
// 所以「比对键」的正确性比实现本身更重要（用 pointId 会得出完全相反的结论）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffReports } from '../src/engine/scanDiff.js';

const report = (scanId, points, vulns) => ({ scanId, points, vulns, finishedAt: '2026-09-11T00:00:00Z', riskLevel: 'High' });

test('同一注入点在两次扫描中 pointId 不同，必须按 location:param:technique 比对', () => {
  // 修复前：id 参数 union 注入命中
  const base = report('scan-a', [{ id: 'aaa111', location: 'url', param: 'id' }], [
    { pointId: 'aaa111', technique: 'union', riskLevel: 'High', description: 'union 注入' },
  ]);
  // 修复后：同一点位，但 pointId 变成 bbb222（每次扫描都会重新生成）
  const cur = report('scan-b', [{ id: 'bbb222', location: 'url', param: 'id' }], [
    { pointId: 'bbb222', technique: 'union', riskLevel: 'High', description: 'union 注入' },
  ]);
  const d = diffReports(base, cur);
  assert.equal(d.remaining.length, 1, '应识别为「仍存在」，而不是新增+修复各一条');
  assert.equal(d.fixed.length, 0);
  assert.equal(d.new.length, 0);
});

test('漏洞被修复：基线有、本次无 → fixed', () => {
  const base = report('scan-a', [{ id: 'a1', location: 'url', param: 'id' }], [
    { pointId: 'a1', technique: 'union', riskLevel: 'High' },
    { pointId: 'a1', technique: 'boolean', riskLevel: 'Medium' },
  ]);
  const cur = report('scan-b', [{ id: 'b1', location: 'url', param: 'id' }], [
    { pointId: 'b1', technique: 'boolean', riskLevel: 'Medium' },
  ]);
  const d = diffReports(base, cur);
  assert.equal(d.fixed.length, 1);
  assert.equal(d.fixed[0].technique, 'union');
  assert.equal(d.remaining.length, 1);
  assert.equal(d.remaining[0].technique, 'boolean');
  assert.equal(d.new.length, 0);
  assert.match(d.summary, /修复 1/);
});

test('新出现的漏洞 → new（回归检测）', () => {
  const base = report('scan-a', [{ id: 'a1', location: 'url', param: 'id' }], []);
  const cur = report('scan-b', [{ id: 'b1', location: 'url', param: 'q' }], [
    { pointId: 'b1', technique: 'error', riskLevel: 'High' },
  ]);
  const d = diffReports(base, cur);
  assert.equal(d.new.length, 1);
  assert.equal(d.new[0].param, 'q');
  assert.equal(d.fixed.length, 0);
});

test('两次都干净 → 三组均为空，summary 可读', () => {
  const d = diffReports(report('a', [], []), report('b', [], []));
  assert.deepEqual([d.fixed.length, d.new.length, d.remaining.length], [0, 0, 0]);
  assert.match(d.summary, /基线 0 条 → 本次 0 条/);
});

test('同参数不同技术位算不同漏洞（不互相掩盖）', () => {
  const base = report('a', [{ id: 'a1', location: 'url', param: 'id' }], [
    { pointId: 'a1', technique: 'union' },
    { pointId: 'a1', technique: 'time' },
  ]);
  const cur = report('b', [{ id: 'b1', location: 'url', param: 'id' }], [
    { pointId: 'b1', technique: 'time' },
  ]);
  const d = diffReports(base, cur);
  assert.equal(d.fixed.length, 1);
  assert.equal(d.fixed[0].technique, 'union');
  assert.equal(d.remaining.length, 1);
  assert.equal(d.remaining[0].technique, 'time');
});

test('缺 points 的降级报告不抛异常', () => {
  const d = diffReports({ vulns: [{ pointId: 'x', technique: 'union' }] }, { vulns: [] });
  assert.equal(d.fixed.length, 1);
  assert.equal(d.fixed[0].param, null);
});

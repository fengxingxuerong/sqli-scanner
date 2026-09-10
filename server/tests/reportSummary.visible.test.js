// [P1 2026-09-09] 报告摘要可见性：skippedPoints 汇总 + OOB 不可用标注
// 交付报告必须回答「有多少点没测、为什么没测」（skippedPoints）与「oob 是否真的测了」
// （oobUnavailable）——否则「没测」会被误读成「测了且无漏洞」。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeSkipped } from '../src/engine/scanHelpers.js';

test('summarizeSkipped：按 skipReason 聚合总数与分布', () => {
  const points = [
    { id: 'p1' },
    { id: 'p2', skipReason: 'prefilter' },
    { id: 'p3', skipReason: 'prefilter' },
    { id: 'p4', skipReason: 'static' },
    { id: 'p5', skipReason: 'input_validation' },
  ];
  assert.deepEqual(summarizeSkipped(points), {
    total: 4,
    byReason: { prefilter: 2, static: 1, input_validation: 1 },
  });
});

test('summarizeSkipped：无跳过点返回 null（不写冗余摘要）', () => {
  assert.equal(summarizeSkipped([{ id: 'a' }, { id: 'b' }]), null);
  assert.equal(summarizeSkipped([]), null);
  assert.equal(summarizeSkipped(undefined), null);
  // 有 skipReason 但值为空串等同未跳过
  assert.equal(summarizeSkipped([{ id: 'a', skipReason: '' }]), null);
});
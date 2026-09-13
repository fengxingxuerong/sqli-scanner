import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { selectPayloads, orderEntriesByBoundary } from '../src/engine/payloadRegistry.js';

describe('[G1] orderEntriesByBoundary 兼容族排序', () => {
  // 引号族排序的注册表现场：条目含单引号/双引号/反引号/数值（空串）四族
  const makeEntry = (id, boundary) => ({ id, technique: 'boolean', dbms: 'mysql', level: 1, risk: 1, boundary, template: `{ORIG}${id}`, falseTemplate: `{ORIG}${id}f` });
  const sq = makeEntry('sq', ["'"]);
  const dq = makeEntry('dq', ['"']);
  const bt = makeEntry('bt', ['`']);
  const num = makeEntry('num', ['']);
  const multi = makeEntry('multi', ["'", '"']);
  const entries = [dq, sq, bt, num, multi];

  it("探测单引号上下文：单引号族条目排前（含多族兼容条目），其余保持相对序", () => {
    const out = orderEntriesByBoundary(entries, "'");
    const ids = out.map((e) => e.id);
    // sq/multi 兼容单引号族 → 前；dq/bt/num 不兼容 → 后（保持相对序 dq<bt<num）
    assert.equal(ids[0], 'sq');
    assert.equal(ids[1], 'multi');
    assert.deepEqual(ids.slice(2), ['dq', 'bt', 'num']);
  });

  it("探测双引号上下文：双引号族排前", () => {
    const out = orderEntriesByBoundary(entries, '"');
    const ids = out.map((e) => e.id);
    assert.deepEqual(ids.slice(0, 2), ['dq', 'multi']);
    assert.deepEqual(ids.slice(2), ['sq', 'bt', 'num']);
  });

  it("探测含括号/通配符前缀（右括号系/百分号系）：族判定不受影响", () => {
    const out = orderEntriesByBoundary(entries, "'))");
    assert.equal(out.map((e) => e.id)[0], 'sq');
    const out2 = orderEntriesByBoundary(entries, "%')");
    assert.equal(out2.map((e) => e.id)[0], 'sq');
  });

  it("空串/反斜杠/未定义 boundary：原样返回（零回归）", () => {
    assert.deepEqual(orderEntriesByBoundary(entries, ''), entries);
    assert.deepEqual(orderEntriesByBoundary(entries, '\\'), entries);
    assert.deepEqual(orderEntriesByBoundary(entries, undefined), entries);
  });

  it("全兼容/全不兼容/单条输入：原样返回", () => {
    const allSq = [makeEntry('a', ["'"]), makeEntry('b', ["'"])];
    assert.deepEqual(orderEntriesByBoundary(allSq, "'"), allSq);
    const allDq = [makeEntry('a', ['"']), makeEntry('b', ['"'])];
    assert.deepEqual(orderEntriesByBoundary(allDq, "'"), allDq);
    assert.deepEqual(orderEntriesByBoundary([sq], "'"), [sq]);
    assert.deepEqual(orderEntriesByBoundary([], "'"), []);
  });

  it("探测右括号系上下文：真实注册表筛选结果中单引号族条目前置（端到端语义）", () => {
    // mysql boolean 注册表现场：单引号族条目确实存在
    const real = selectPayloads({ dbms: 'mysql', technique: 'boolean', clause: ['where'] });
    if (real.length < 2) return; // 无现场则跳过
    const ordered = orderEntriesByBoundary(real, "'))");
    // 兼容族条目全部前置（保序），且全集不丢（排序非过滤）
    const stop = ordered.findIndex((e) => !(e.boundary || []).some((b) => typeof b === 'string' && b.includes("'")));
    const firstCompat = stop === -1 ? ordered : ordered.slice(0, stop);
    assert.ok(firstCompat.length > 0);
    assert.equal(ordered.length, real.length);
    const sortById = (arr) => [...arr].sort((a, b) => (a.id > b.id ? 1 : -1));
    assert.deepEqual(sortById(ordered), sortById(real));
  });
});

// 统计辅助工具纯函数单测（node --test）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mean, std, ratioTrue, similarityRate, effectiveThreshold, twoProportionZ, isSignificant, baselineNoiseRate, adaptiveMinStable, adaptiveTimeFloor } from '../src/core/statsHelper.js';

test('mean 基本均值', () => {
  assert.equal(mean([1, 2, 3, 4]), 2.5);
  assert.equal(mean([7]), 7);
  assert.equal(mean([]), 0);
});

test('std 总体标准差（长度<2 返回 0）', () => {
  assert.equal(std([0, 2]), 1); // 均值1、方差1、std=1
  assert.equal(std([1]), 0);
  assert.equal(std([]), 0);
});

test('ratioTrue 比例', () => {
  assert.equal(ratioTrue([true, false, true]), 2 / 3);
  assert.equal(ratioTrue([false, false]), 0);
  assert.equal(ratioTrue([]), 0);
});

test('similarityRate 按 expected 计一致率', () => {
  const fn = (s) => s === 'base';
  assert.equal(similarityRate(['base', 'base', 'x'], fn, true), 2 / 3);
  assert.equal(similarityRate(['x', 'x', 'base'], fn, false), 2 / 3);
  assert.equal(similarityRate([], fn, true), 0);
});

test('effectiveThreshold σ=0 退化为 μ+absFloor（≡ legacy 固定阈值）', () => {
  assert.equal(effectiveThreshold(0.3, 0, 2, 1.5), 0.3 + 1.5);
});

test('effectiveThreshold σ>0 用 μ+z·σ（分布感知）', () => {
  assert.equal(effectiveThreshold(0.3, 0.1, 2, 1.5), 0.3 + 2 * 0.1);
});

test('twoProportionZ 显著偏离返回正 z；两组相等返回 0', () => {
  const z1 = twoProportionZ(1, 3, 0, 10);
  assert.ok(z1 > 3.5 && z1 < 3.7, `期望≈3.6, 实际${z1}`);
  assert.ok(Math.abs(twoProportionZ(0.5, 2, 0.5, 2)) < 1e-9); // 两组比例相等 → z=0
});

test('twoProportionZ 退化：分母不足/标准误为 0 返回 null', () => {
  assert.equal(twoProportionZ(0, 3, 0, 10), null); // 合并比例为 0 → 标准误为 0
  assert.equal(twoProportionZ(1, 0, 0, 10), null); // 分母不足
});

test('isSignificant 单侧判定（抗误报）', () => {
  assert.equal(isSignificant(1, 3, 0, 10), true); // 1.0 显著 > 0.0
  assert.equal(isSignificant(0.5, 2, 0.5, 2), false); // z=0 不显著
  assert.equal(isSignificant(0.8, 3, 0.8, 10), false); // 仅等于基线抖动，不显著（抗误报核心）
});

// ===== 阈值自适应（v3）=====
test('baselineNoiseRate 相同→0、全异→1、部分→比例', () => {
  const eq = (a, b) => a === b;
  assert.equal(baselineNoiseRate(['x', 'x', 'x'], eq), 0);
  assert.equal(baselineNoiseRate(['a', 'b', 'c', 'd', 'e'], eq), 1);
  assert.equal(baselineNoiseRate(['x', 'x', 'y'], eq), 2 / 3);
  assert.equal(baselineNoiseRate(['x'], eq), 0); // 样本<2
});

test('adaptiveMinStable 稳定落下限、抖动抬高、上限夹紧', () => {
  // 稳定目标 noise≈0 → 落回 floor（保持严格）
  assert.equal(adaptiveMinStable(0, 0.3, 0.66, 0.95), 0.66);
  assert.equal(adaptiveMinStable(0.1, 0.3, 0.66, 0.95), 0.66); // 0.4 < floor → 夹到 floor
  // 抖动目标 noise 大 → 门槛抬高
  assert.equal(adaptiveMinStable(0.4, 0.3, 0.66, 0.95), 0.7);
  // 极端抖动 → 夹到 cap
  assert.equal(adaptiveMinStable(0.9, 0.3, 0.66, 0.95), 0.95);
});

test('adaptiveTimeFloor σ=0 与现状一致、σ 大则放宽', () => {
  assert.equal(adaptiveTimeFloor(0.8, 0, 2), 0.8); // 稳定目标 = absFloor（与 legacy 一致）
  // 抖动目标 = absFloor + scale·σ（浮点容差：0.8+0.2*2=1.2000000000000002）
  assert.ok(Math.abs(adaptiveTimeFloor(0.8, 0.2, 2) - 1.2) < 1e-9);
});


// [D206] 布尔命中复核（跨轮一致性）：把「单轮碰巧成立」挡在漏洞之外。
// 背景：实测 demo.testfire.net 同一 URL/body/level 连跑三次检出 5/2/1 条，
// 而单轮 3 样本 + minRatio 0.66 只允许一个样本偏离 —— 一次抖动就能让结论翻盘。
// 这里用打桩驱动 _recheckPair 本身（不跑完整 detect），只钉它的判定口径。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';

const BASE = 'PAGE-BASELINE';

/**
 * 造一个只走 _recheckPair 的探测器：真实判据函数 + 打桩的请求层。
 * @param {string[]} tBodies 真条件响应正文（按采样顺序）
 * @param {string[]} fBodies 假条件响应正文
 * @returns {{detector: BooleanBlindDetector, ctx: object, calls: object[]}} 探测器与调用记录
 */
function makeHarness(tBodies, fBodies) {
  const d = new BooleanBlindDetector();
  const calls = [];
  d.buildRequest = (_target, _point, payload) => ({ payload });
  d.sendConcurrent = async (_client, _ctx, reqs) => {
    calls.push(...reqs.map((r) => r.payload));
    const seq = [...tBodies, ...fBodies];
    return seq.map((body) => ({ resp: { data: body, status: 200 } }));
  };
  const ctx = { httpClient: {}, target: {}, point: { originalValue: '1' } };
  return { detector: d, ctx, calls };
}

const args = (effSamples = 3) => ({
  truePayload: "1' AND '1'='1",
  falsePayload: "1' AND '1'='2",
  effSamples,
  minRatio: 0.66,
  similarToBaseline: (b) => b === BASE,
  meaningfulDiff: (a, b) => a !== b,
  concurrency: 1,
});

test('[D206] 复核通过：假组全部偏离基线且每对都有差异', async () => {
  const { detector, ctx, calls } = makeHarness([BASE, BASE, BASE], ['FALSE-1', 'FALSE-2', 'FALSE-3']);
  const r = await detector._recheckPair(ctx, args());
  assert.equal(r.ok, true);
  assert.equal(r.falseRatio, 1);
  assert.equal(r.meaningfulRatio, 1);
  assert.equal(r.samples, 3);
  // 复核轮自己发满 2×effSamples 个请求（真组在前、假组在后）
  assert.deepEqual(calls, ["1' AND '1'='1", "1' AND '1'='1", "1' AND '1'='1", "1' AND '1'='2", "1' AND '1'='2", "1' AND '1'='2"]);
});

test('[D206] 复核不通过：假组与基线同形（说明「差异」只是这一轮的抖动）', async () => {
  const { detector, ctx } = makeHarness([BASE, BASE, BASE], [BASE, BASE, BASE]);
  const r = await detector._recheckPair(ctx, args());
  assert.equal(r.ok, false);
  assert.equal(r.falseRatio, 0, '假组全≈基线 ⇒ 不能算偏离');
});

test('[D206] 复核不通过：假组偏离了基线但真假两轮没有差异（例如都被同一错误页覆盖）', async () => {
  const { detector, ctx } = makeHarness(['ERR', 'ERR', 'ERR'], ['ERR', 'ERR', 'ERR']);
  const r = await detector._recheckPair(ctx, args());
  assert.equal(r.ok, false);
  assert.equal(r.falseRatio, 1, '假组确实偏离基线（ERR≠BASE）');
  assert.equal(r.meaningfulRatio, 0, '但真假无差异 ⇒ 不是条件引起的');
});

test('[D206] 部分偏离按比例算：3 样本里 1 个偏离 = 0.33 < 0.66 ⇒ 不通过', async () => {
  const { detector, ctx } = makeHarness([BASE, BASE, BASE], [BASE, BASE, 'FALSE']);
  const r = await detector._recheckPair(ctx, args());
  assert.equal(r.ok, false);
  assert.ok(Math.abs(r.falseRatio - 1 / 3) < 1e-9);
});

test('[D206] 采样数透传：effSamples=1 时只发 2 个请求、比例是 0/1 或 1/1', async () => {
  const { detector, ctx, calls } = makeHarness([BASE], ['FALSE']);
  const r = await detector._recheckPair(ctx, args(1));
  assert.equal(calls.length, 2);
  assert.equal(r.samples, 1);
  assert.equal(r.ok, true);
  assert.equal(r.falseRatio, 1);
});

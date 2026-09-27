// ============================================================================
// tests/tokenBagSimilar.test.js —— HTML 动态页「标签边界 token 袋」骨架判定的回归钉
// [P1-FLAKY 2026-09-27] noisy 强动态页布尔漏检（CI 1/5 复现率）的根因修复钉子。
//
// 病根回顾：fixed-offset 分块对内容位移不鲁棒——变长动态段之后所有 64B 块边界错位、
// 块序打乱叠加，dynamicBlockFilter 在「全动态/半动态」两态间翻硬币（load-repro.mjs
// 负载实测 noise=0.00/0.40 两态），半动态态下门槛抬高 → 真样本对齐运气 0 → 漏检。
//
// 本文件全部为纯 JS 模拟（不依赖真 MySQL）：种子化 PRNG 生成与 /noisy 同构的页面，
// 断言 token 袋骨架判定的语义与门控切换。真引擎侧由 real-mysql-lab verify.mjs 守护。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTokenBagSimilarFn,
  similarityRate,
} from '../src/core/statsHelper.js';
import { buildDynamicSimilarGated, buildDynamicSimilarFn } from '../src/engine/Detector.js';

/** mulberry32 种子化 PRNG：测试完全确定，又覆盖随机内容空间 */
function mulberry32(seed) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** 与 /noisy 同构的强动态页：变长随机段 + 随机块序 + 可选结果行 */
function makeNoisyPage(rnd, { withRow = true } = {}) {
  const hex = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 16).toString(16)).join('');
  const b36 = () => Math.floor(rnd() * 1e9).toString(36);
  const blocks = [
    `<div class="stat">ts=${1700000000000 + Math.floor(rnd() * 1e6)}</div>`,
    `<div class="sid">session=${hex(32)}</div>`,
    `<div class="mx">${Array.from({ length: 12 }, () => `<span data-k="${hex(16)}">${b36()}</span>`).join('')}</div>`,
    `<div class="ad" id="${hex(24)}">rec-${b36()}</div>`,
  ];
  for (let i = blocks.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [blocks[i], blocks[j]] = [blocks[j], blocks[i]];
  }
  const row = withRow ? '<table><tr><td>1</td><td>alice</td></tr></table>' : '<p>empty</p>';
  return `<html><head><title>feed</title></head><body>\n${blocks.join('\n')}\n${row}\n<div class="ft">gen=${b36()}</div></body></html>`;
}

test('token 袋骨架：基线两两恒相似（噪声地板=0），随机内容/变长/洗牌免疫', () => {
  const rnd = mulberry32(42);
  const baselines = Array.from({ length: 5 }, () => makeNoisyPage(rnd));
  const fn = buildTokenBagSimilarFn(baselines);
  assert.ok(fn, 'HTML 基线应产出 token 判据');
  for (let i = 0; i < baselines.length; i++) {
    for (let j = 0; j < baselines.length; j++) {
      assert.equal(fn(baselines[i], baselines[j]), true, `基线 ${i}~${j} 应相似`);
    }
  }
  const fresh = makeNoisyPage(rnd);
  assert.equal(fn(fresh, baselines[0]), true, '同骨架新页面（随机内容全换）应相似');
});

test('token 袋骨架：假条件缺失结果行 → 判不相似（布尔信号保留）', () => {
  const rnd = mulberry32(7);
  const baselines = Array.from({ length: 5 }, () => makeNoisyPage(rnd, { withRow: true }));
  const fn = buildTokenBagSimilarFn(baselines);
  const falseBody = makeNoisyPage(rnd, { withRow: false });
  assert.equal(fn(falseBody, baselines[0]), false, '缺结果行的假响应应判不相似');
});

test('token 袋骨架：骨架来自基线内容——空结果基线下带行探针判不相似（提取层方向）', () => {
  const rnd = mulberry32(11);
  const baselines = Array.from({ length: 3 }, () => makeNoisyPage(rnd, { withRow: false }));
  const fn = buildTokenBagSimilarFn(baselines);
  assert.equal(fn(makeNoisyPage(rnd, { withRow: false }), baselines[0]), true);
  assert.equal(fn(makeNoisyPage(rnd, { withRow: true }), baselines[0]), false, '带行探针缺骨架 token → 判不相似');
});

test('边界回退：基线不足 / 非 HTML / 无稳定骨架 → null（调用方回退现状）', () => {
  const rnd = mulberry32(3);
  assert.equal(buildTokenBagSimilarFn([makeNoisyPage(rnd)]), null, '基线 <2');
  assert.equal(buildTokenBagSimilarFn(['alpha beta gamma', 'alpha beta delta']), null, '非 HTML（无 <）');
  assert.equal(buildTokenBagSimilarFn(['<a>1</a>', '<b>2</b>', '<c>3</c>']), null, 'HTML 但零共享 token');
});

test('种子化 noisy 全链模拟：20 轮随机动态内容下三一致率全 1.00（flake 回归钉）', () => {
  const rnd = mulberry32(20260927);
  for (let round = 0; round < 20; round++) {
    const baselines = Array.from({ length: 5 }, () => makeNoisyPage(rnd, { withRow: true }));
    const fn = buildDynamicSimilarGated(baselines, { autoDynamicBlock: true });
    assert.ok(fn, `第${round}轮应产出判据`);
    const similarToBaseline = (b) => baselines.some((bl) => fn(b, bl));
    const meaningfulDiff = (a, b) => !fn(a, b);
    const tBodies = Array.from({ length: 4 }, () => makeNoisyPage(rnd, { withRow: true }));
    const fBodies = Array.from({ length: 4 }, () => makeNoisyPage(rnd, { withRow: false }));
    const trueRatio = similarityRate(tBodies, similarToBaseline, true);
    const falseRatio = similarityRate(fBodies, similarToBaseline, false);
    let meaningfulHits = 0;
    for (let s = 0; s < 4; s++) if (meaningfulDiff(tBodies[s], fBodies[s])) meaningfulHits++;
    assert.equal(trueRatio, 1, `第${round}轮 trueRatio=${trueRatio}（真样本应全相似）`);
    assert.equal(falseRatio, 1, `第${round}轮 falseRatio=${falseRatio}（假样本应全不相似）`);
    assert.equal(meaningfulHits / 4, 1, `第${round}轮 meaningfulRatio=${meaningfulHits / 4}`);
  }
});

test('门控：autoDynamicBlock 非 true → null；显式 true → 产出判据', () => {
  const rnd = mulberry32(5);
  const baselines = Array.from({ length: 5 }, () => makeNoisyPage(rnd));
  assert.equal(buildDynamicSimilarGated(baselines, undefined), null);
  assert.equal(buildDynamicSimilarGated(baselines, {}), null);
  assert.equal(buildDynamicSimilarGated(baselines, { autoDynamicBlock: false }), null);
  assert.ok(buildDynamicSimilarGated(baselines, { autoDynamicBlock: true }));
});

test('门控：位移退化（占比≥0.3）切 token 判据 —— 大长度位移免疫，positional 对照被长度容差挡下', () => {
  // 动态段放页尾（错位区 ~26%<30% 不触发切换的对照造不出来时）——这里动态段在页中，
  // 错位区占后半页 ≥30% → 门控切换；变长块 100→500 的 Δlen=400 远超 12% 长度容差。
  const rows = Array.from({ length: 30 }, () => '<tr><td>x</td></tr>').join('');
  const mk = (k) =>
    `<html><body><table>${rows}</table><div>${'x'.repeat(k)}</div><table><tr><td>row</td></tr></table></body></html>`;
  const baselines = [mk(100), mk(300), mk(500)];
  const fn = buildDynamicSimilarGated(baselines, { autoDynamicBlock: true });
  const probe = mk(250);
  assert.equal(fn(probe, baselines[0]), true, 'token 判据应免疫长度位移');
  // 对照：同两个基线喂旧 positional 判据 → 长度容差挡下（证明门控确实切换了语义）
  const pos = buildDynamicSimilarFn(baselines);
  assert.equal(pos(probe, baselines[0]), false, 'positional 判据应被 12% 长度容差挡下');
});

// ============================================================================
// tests/similarityLengthTolerance.test.js
// 相似度判据的长度容差必须是**单一真源**，且 null 不得崩溃
//
// ── 问题（实测确认）────────────────────────────────────────────────────────
// engine/detectorSupport/similarity.js 同一文件里有两份相似度判定：
//   · chunkedSimilar（静态分块比对，Detector.prototype.chunkedSimilar）
//   · buildDynamicSimilarFn（动态块过滤版，检测层与提取层共用）
//
// 两者的**长度容差判据逐字重复**：
//     if (Math.abs(la - lb) > Math.max(24, Math.max(la, lb) * 0.12)) return false;
//     if (Math.abs(sa.length - sb.length) > Math.max(24, Math.max(sa.length, sb.length) * 0.12)) ...
// 仅变量名不同。实测长度网格 0..200 × 0..200 共 40401 组，两种写法逐点等价 ——
// 说明它确实是**同一判据的两份实现**，不是两个碰巧相同的阈值。
//
// 这正是 core/http/ipBytes.js 注释里警告过的形态：
//   「同一判据多份实现，一份修了另一份没修」—— 本仓反复吃过这个亏。
//
// ── 附带缺口（当前不可达，但属公共 API 防御）──────────────────────────────
// chunkedSimilar 直接读 `a.length`，传 null/undefined 会抛 TypeError：
//     chunkedSimilar(null, 'x') → TypeError: Cannot read properties of null
//     chunkedSimilar('x', undefined) → TypeError: ...
// 而同一文件的 buildDynamicSimilarFn 有防护（`String(a ?? '')`）。
//
// 实测两个调用点（boundary.js:203 / :269）都先经 stripEchoedPayload，
// 它把 null 归一为 ""（实测 stripEchoedPayload(null) === ""），故当前不可达。
// 但 chunkedSimilar 挂在 Detector.prototype 上是**公共 API**，JSDoc 声明
// @param {string} 却无运行时防护 —— 与同文件另一份判据口径不一致。
//
// ⚠️ 诚实标注：null 崩溃是**防御性缺口**，不是实测可达的缺陷。
// 本组的价值在于把两份判据钉成一份，防止今后改一份漏一份。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chunkedSimilar, buildDynamicSimilarFn, normBody } from '../src/engine/detectorSupport/similarity.js';

const SRC = readFileSync(
  fileURLToPath(new URL('../src/engine/detectorSupport/similarity.js', import.meta.url)),
  'utf8',
);

/** 剥掉注释，避免注释里的示例被判为实现残留 */
const CODE = SRC.replace(/^\s*(?:\/\/|\*|\/\*).*$/gm, '');

test('自证-0) 判据本身有效：长度差超过容差时必须判不相似（否则本组守卫前提失效）', () => {
  assert.equal(chunkedSimilar('a'.repeat(100), 'b'.repeat(500)), false,
    '长度 100 vs 500（差 400 > 容差）竟判相似 —— 判据失效');
  assert.equal(chunkedSimilar('a'.repeat(100), 'a'.repeat(110)), true,
    '长度 100 vs 110（差 10 ≤ 容差）且内容相同，应判相似');
});

test('自证-1) 长度容差阈值 = max(24, max(la,lb) × 0.12)（不得被改）', () => {
  // ⚠️ 容差**不是固定 24**：它随 max(la,lb) 线性增长，只有在 max < 200 时
  // 才等于 24（24/0.12 = 200）。初版这里把它当常数写死，断言直接红 ——
  // 是断言错了，不是实现错了。
  const tol = (la, lb) => Math.max(24, Math.max(la, lb) * 0.12);
  for (const [la, lb] of [[100, 124], [100, 125], [200, 226], [200, 228], [1000, 1134], [1000, 1136]]) {
    const base = 'x'.repeat(la);
    const other = 'x'.repeat(la) + 'y'.repeat(lb - la);
    const expect = Math.abs(la - lb) <= tol(la, lb);
    assert.equal(chunkedSimilar(base, other), expect,
      `la=${la} lb=${lb}（容差 ${tol(la, lb)}）判定与阈值不符`);
  }
  // 24 是小 body 的下限：max < 200 时容差恒为 24
  assert.equal(tol(50, 74), 24, '小 body 时容差应为下限 24');
  assert.equal(tol(1000, 120), 120, '大 body 时容差应随长度增长');
});

test('缺陷-1) 长度容差判据在文件里只能出现一次（消除重复实现）', () => {
  // 匹配 `Math.abs(<两长度> 之差) <比较符> Math.max(24, ...)` 这一形态，
  // **两种比较符都算**（`>` 拒绝 / `<=` 接受 是同一判据的两种写法）。
  const TOLERANCE = /Math\.abs\(\s*\w+(?:\.length)?\s*-\s*\w+(?:\.length)?\s*\)\s*[<>]=?\s*Math\.max\(\s*24\s*,/g;
  const hits = CODE.match(TOLERANCE) || [];
  assert.equal(hits.length, 1,
    `长度容差判据出现 ${hits.length} 次（应只 1 次）：\n  ${hits.join('\n  ')}\n`
    + '⇒ 又一份副本。改阈值时会漏改一处，这正是本组守卫要防的。');
});

test('缺陷-2) chunkedSimilar 不得因 null/undefined 崩溃（公共 API 防御）', () => {
  for (const [label, a, b] of [
    ['null, "x"', null, 'x'],
    ['"x", null', 'x', null],
    ['undefined, "x"', undefined, 'x'],
    ['"x", undefined', 'x', undefined],
    ['null, null', null, null],
    ['undefined, undefined', undefined, undefined],
  ]) {
    let r;
    try {
      r = chunkedSimilar(a, b);
    } catch (e) {
      assert.fail(`chunkedSimilar(${label}) 抛异常：${e.message} —— 公共 API 不得崩溃`);
    }
    assert.equal(typeof r, 'boolean', `chunkedSimilar(${label}) 应返回 boolean`);
  }
});

test('契约-3) null 必须归一为"空响应"而非字符串 "null"/"undefined"', () => {
  // ⚠️ 初版断言写成 `chunkedSimilar(null, 'null') === true`，那是**断言错了**：
  // null 归一为 ""，而 "" 与字面量 "null" 是两段不同内容，chunkSimilarity
  // 实测为 0 ⇒ 判**不相似**是正确行为。"null" 是一次真实的 4 字符正文，
  // 空响应不该被当成它。
  //
  // 真正要钉的是：null/undefined 的归一结果与空串**完全同形**。
  // 若误用 String(v)，String(null) === "null"（4 字符），于是
  // chunkedSimilar(null, "") 会走 "null"(4) vs ""(0) 这条路 —— 结果不同。
  const cases = [
    [null, undefined], [null, null], [undefined, undefined],
    [null, ''], [undefined, ''], ['', ''],
  ];
  for (const [a, b] of cases) {
    assert.equal(chunkedSimilar(a, b), true,
      `chunkedSimilar(${JSON.stringify(a)}, ${JSON.stringify(b)}) 应判相似`
      + '（两者都是"无响应"，必须同形）');
  }
  // 归一为 "" 后仍须与真实正文区分
  assert.equal(chunkedSimilar(null, 'abcd'), false, '空响应 vs 4 字符正文应判不相似');
  assert.equal(chunkedSimilar(undefined, 'abcd'), false, 'undefined vs 4 字符正文应判不相似');
});

test('契约-4) 两份判据必须共用同一个归一函数（钉归一口径，不钉最终判定值）', () => {
  // ⚠️ 初版断言 `f(a,b) === chunkedSimilar(a,b)`，那是**断言错了**：
  // 两份判据本就该给出不同结果 —— chunkedSimilar 有独立的空值分支
  // （空 vs 非空 ⇒ 不相似），buildDynamicSimilarFn 没有（它按分块相似率算，
  // `total === 0` 时返回 true）。实测 (0,'') 分叉正是这个设计差异，不是缺陷。
  //
  // 所以真正要钉的是**归一化口径**：两份判据必须走同一个 normBody。
  // ⚠️ 切片必须只取 **buildDynamicSimilarFn 的函数体**。
  // 初版从该函数名一直切到文件末尾，把后面的 buildDynamicSimilarGated
  // 也圈了进来 —— 那里的 `String(b ?? '')` 是对**基线数组元素**的归一，
  // 与响应体归一是两件事，被误判成"残留"。判据必须比被测对象更精确。
  const start = CODE.indexOf('export function buildDynamicSimilarFn');
  assert.ok(start >= 0, '未找到 buildDynamicSimilarFn');
  const end = CODE.indexOf('\nexport ', start + 1);
  const fnBody = CODE.slice(start, end < 0 ? undefined : end);
  assert.ok(/const sa = normBody\(a\);/.test(fnBody),
    'buildDynamicSimilarFn 未调用 normBody —— 又一份自写的归一实现');
  assert.ok(!/String\([ab]\s*\?\?\s*''\)/.test(fnBody),
    "buildDynamicSimilarFn 里残留 String(x ?? '') —— 与 normBody 口径分叉");

  // 归一化本身的口径（normBody 是导出的单一真源，直接测它）
  assert.equal(normBody(null), '', 'normBody(null) 应为 ""（无 body = 空响应）');
  assert.equal(normBody(undefined), '', 'normBody(undefined) 应为 ""');
  assert.equal(normBody(0), '0', 'normBody(0) 应为 "0" —— 0 是假值但不是"缺失"');
  assert.equal(normBody(false), 'false', 'normBody(false) 应为 "false"');
  assert.equal(normBody(''), '', 'normBody("") 应为 ""');
  assert.equal(normBody('abc'), 'abc', 'normBody 对字符串应原样返回');

  // 同形的输入在两份判据上必须给出相同结果（这两组实测一致）
  const baselines = ['baseline body content here', 'baseline body content here!'];
  const f = buildDynamicSimilarFn(baselines);
  if (!f) return;   // 无动态块时该构建器按设计返回 null
  for (const [a, b] of [[null, undefined], [null, null], ['', ''], [0, 0], [false, false], [0, '0']]) {
    assert.equal(f(a, b), chunkedSimilar(a, b),
      `同形输入 (${JSON.stringify(a)}, ${JSON.stringify(b)}) 在两份判据上结果不一致`);
  }
});

test('契约-5) 空值分支不得因抽取容差判据而被删（它未被容差覆盖）', () => {
  // la===0,lb=5：长度差 5 ≤ 容差 24 ⇒ 容差判据**放行**，但 chunkedSimilar
  // 仍有独立的空值分支返回 la===lb ⇒ false。若误以为"容差已覆盖"而删掉
  // 该分支，这里会变成 true —— 语义漂移。
  assert.equal(chunkedSimilar('', 'abcde'), false, '空串 vs 5 字符应判不相似（走空值分支）');
  assert.equal(chunkedSimilar('abcde', ''), false, '5 字符 vs 空串应判不相似');
  assert.equal(chunkedSimilar('', ''), true, '双空串应判相似');
});
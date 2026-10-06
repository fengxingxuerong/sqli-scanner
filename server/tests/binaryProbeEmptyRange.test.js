// ============================================================================
// tests/binaryProbeEmptyRange.test.js
// binaryProbe 在**空区间（lo > hi）**下不得误报"顶到上限"并触发第 2 段
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// engine/binaryProbe.js 的 runOnce：
//
//   let a = lo, b = hi, ans = lo - 1;
//   while (a <= b) { ... }          ← lo > hi 时循环体一次都不执行
//   return { n: ans, reliable };    ← ans = lo - 1，正好落在 hi 上
//
// 外层：
//   if (r.n < hi) return { ...r, capped: false };
//   ... else 进第 2 段形态自检（多发 2 次探测：endShape(probe, lo, hi, shape)）
//
// 当 lo = hi + 1（空区间）时：ans = lo - 1 = hi ⇒ `r.n < hi` 为假
// ⇒ **"一个探测点都没做过"被报告成"顶到上限，判据可能已失效"**，
//    触发第 2 段形态自检，白白多发 probe(lo) / probe(hi) 两个请求。
//
// 而 probe(lo) 里的 lo **不是合法候选**（它 > hi，从不在搜索区间内），
// 拿它当"判据为真"的基准点在语义上就是错的。
//
// ── 两个调用点都可达（实测）────────────────────────────────────────────────
// ① columnGuess.binaryGuessColumns({ maxCols })：maxCols 来自 --union-cols 配置
//    实测 maxCols=0 ⇒ 探测序列 [1, 0] —— 后两个正是 endShape 的 lo/hi 调用。
//    maxCols=-1 ⇒ [1,-1]；maxCols=NaN ⇒ [1,NaN]。
// ② blindExtractor：range.lo ?? 0 / range.hi ?? 255，范围配置写反即触发。
//
// ── 为什么是缺陷而不只是浪费 ───────────────────────────────────────────────
// 调用方约定（binaryProbe.js 头部 JSDoc）：
//   capped = "二分顶到上界且备份判据不可区分" ⇒ 判据已失效，**调用方须放弃**
// columnGuess：`if (capped) return null;` —— 列数返回 null，UNION 直接放弃。
// 而空区间**根本没探测过**，判据既没有被验证也没有失效，
// 却因为这个假 capped 而被当成"失效"处理 ⇒ 无谓放弃一条本可走通的路径。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { binaryProbe } from '../src/engine/binaryProbe.js';
import { binaryGuessColumns } from '../src/engine/columnGuess.js';

const neverOver = () => false;
const shape = (res) => String(res?.body ?? '');

/** 记录 probe 调用序列的探针工厂。骨架**与 n 无关**（见 自证-1 的说明）。 */
function tracer(body = 'ok') {
  const calls = [];
  const probe = async (n) => {
    calls.push(n);
    return { status: 200, body, len: n };
  };
  return { probe, calls };
}

test('自证-0) 单点区间 lo===hi 且判据恒假时 capped=true 是**正确**行为（否则本组守卫前提失效）', async () => {
  // lo===hi 时确实探测了那个点、确实顶到上界 ⇒ capped=true 正确。
  // 本组守卫只针对 lo > hi 的**空区间**，不得把这两种情况混为一谈。
  const { probe, calls } = tracer();
  const r = await binaryProbe(probe, { lo: 5, hi: 5, judge: neverOver, shape, direction: 'gt' });
  assert.deepEqual(calls, [5, 5, 5], '单点区间应探测 lo 并做形态自检');
  assert.equal(r.capped, true, '单点区间顶到上界 ⇒ capped=true 正确');
});

test('自证-1) lo=1,hi=4 且判据恒假（真实顶到上界）时 capped=true 正确', async () => {
  // ⚠️ 骨架必须**与 n 无关**（如 'ok'）：若骨架含 n（如 `resp-for-${n}`），
  // 第 2 段的备份判据 `shape(res) === failShape` 只在 n=hi 处成立 →
  // over=true → 上界收缩到 hi-1，n 变成 3。那是备份判据的正确行为，
  // 不是本组守卫要测的东西（用这种骨架会让断言测到别的事上去）。
  const calls = [];
  const probe = async (n) => { calls.push(n); return { status: 200, body: 'ok', len: n }; };
  const r = await binaryProbe(probe, {
    lo: 1, hi: 4, judge: neverOver, shape: (res) => String(res?.body ?? ''), direction: 'gt',
  });
  assert.equal(r.capped, true, '真实顶到上界时 capped 应为 true');
  assert.equal(r.n, 4, '判据恒假 ⇒ 答案就是上界 hi');
});

test('缺陷-1) 空区间 lo>hi 不得被误报为 capped=true', async () => {
  const { probe } = tracer();
  const r = await binaryProbe(probe, { lo: 5, hi: 4, judge: neverOver, shape, direction: 'gt' });
  assert.equal(r.capped, false,
    `空区间（lo=5 > hi=4）返回 capped=true ⇒ "从未探测"被误报成"顶到上限/判据失效"`);
});

test('缺陷-2) 空区间不得触发第 2 段形态自检（probe(lo) 不是合法候选点）', async () => {
  const { probe, calls } = tracer();
  await binaryProbe(probe, { lo: 5, hi: 4, judge: neverOver, shape, direction: 'gt' });
  assert.ok(!calls.includes(5),
    `探测了非法候选点 lo=5（它 > hi，不在搜索区间内）：实际调用 ${JSON.stringify(calls)}`);
  assert.deepEqual(calls, [], `空区间应当一个探测点都不发，实际发了 ${calls.length} 次`);
});

test('缺陷-3) 空区间的 n 不得被下游当成真实答案（capped 是唯一的区分信号）', async () => {
  // ⚠️ 这里刻意**不断言 n !== hi**：lo-1 与 hi 在空区间时必然相等
  // （lo = hi+1 ⇒ lo-1 = hi），这是结构性撞车，改不掉也不该改 ——
  // n = lo-1 是 helper 一贯的"没找到"表示（lt 方向判据恒假时同样是 lo-1，
  // 契约-5 已钉住）。
  //
  // 真正的区分信号是 capped：空区间 capped=false ⇒ 调用方不会把它当
  // "判据失效"而放弃。这里钉住的是「capped 正确 ⇒ 契约成立」，
  // 而不是「n 必须看起来不一样」——后者会让守卫逼出一个错误的改法。
  const { probe } = tracer();
  const r = await binaryProbe(probe, { lo: 5, hi: 4, judge: neverOver, shape, direction: 'gt' });
  assert.equal(r.capped, false, 'capped 必须为 false，这正是区分信号');
  assert.equal(r.reliable, false, '一个探测点都没做过 ⇒ reliable 不得为 true');
  // 与真实顶界的情形对照：同样是 n === hi，靠 capped 区分
  const real = await binaryProbe(tracer().probe, { lo: 1, hi: 4, judge: neverOver, shape, direction: 'gt' });
  assert.equal(real.n, r.n, '两者 n 相同 ⇒ 只能靠 capped 区分，断言 n 的差异是错的');
  assert.notEqual(real.capped, r.capped, 'capped 必须能把"真顶界"和"空区间"区分开');
});

test('缺陷-4) columnGuess 传越界 maxCols 时不得因此放弃（探测序列不得含非法候选点）', async () => {
  for (const maxCols of [0, -1, NaN]) {
    const { probe, calls } = tracer();
    const r = await binaryGuessColumns(probe, { baseLen: 100, maxCols });
    assert.ok(!calls.includes(maxCols) || maxCols === 0,
      `maxCols=${maxCols} 时探测了越界候选点：${JSON.stringify(calls)}`);
    // 不因假 capped 而返回 null（那是"判据失效"的信号）
    assert.notEqual(r, null,
      `maxCols=${maxCols}（空区间）返回 null ⇒ 被当成"判据失效"而放弃，但压根没探测过`);
  }
});

test('契约-5) 非空区间的行为不得被本修复改变（lo<hi 与 lo===hi 全部照旧）', async () => {
  // gt 方向：judge 恒假 ⇒ 一路推到 hi，capped=true（真顶上界）
  const a = await binaryProbe(tracer().probe, { lo: 1, hi: 8, judge: neverOver, shape, direction: 'gt' });
  assert.equal(a.n, 8);
  assert.equal(a.capped, true);

  // gt 方向：judge 在 mid=4 处翻转 ⇒ 应收敛到 4，不 capped
  const b = await binaryProbe(tracer().probe, {
    lo: 1, hi: 8, judge: (res) => res.len > 4, shape, direction: 'gt',
  });
  assert.equal(b.n, 4, 'gt 方向收敛点错误');
  assert.equal(b.capped, false);

  // lt 方向：判据恒假 ⇒ ans 停在 lo-1 = -1，不 capped
  const c = await binaryProbe(tracer().probe, { lo: 0, hi: 8, judge: neverOver, shape, direction: 'lt' });
  assert.equal(c.n, -1, 'lt 方向"全假"应返回 lo-1 = -1');
  assert.equal(c.capped, false);
});

test('契约-6) lo===hi 与 lo>hi 必须被区别对待（这正是本修复的边界）', async () => {
  const single = await binaryProbe(tracer().probe, { lo: 4, hi: 4, judge: neverOver, shape, direction: 'gt' });
  const empty = await binaryProbe(tracer().probe, { lo: 5, hi: 4, judge: neverOver, shape, direction: 'gt' });
  assert.equal(single.capped, true, 'lo===hi 探测过该点，顶到上界 ⇒ capped=true');
  assert.equal(empty.capped, false, 'lo>hi 一个点都没探测 ⇒ 不得报 capped');
});
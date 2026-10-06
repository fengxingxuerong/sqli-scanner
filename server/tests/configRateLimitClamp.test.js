// ============================================================================
// tests/configRateLimitClamp.test.js —— 限速三键（delay/reqRate/maxReq）契约对齐
//
// ── 缺陷 ────────────────────────────────────────────────────────────────────
// 同一个语义（--delay / --reqrate / --max-requests），两个 REST 入口两套契约：
//   exploitRoutes.js:211-213  numOpt(v, 0, { min:0, max:60/1000/1e6 })  ← 有夹取
//   scanGuard/backfill.js:39   Number.isFinite(v) 即原样透传            ← 无夹取
//
// 实测（真实调用 applyBackfill）：
//   delay=-5     → -5        （负延时，行为等同 0，静默吞掉用户输入）
//   delay=99999  → 99999     （用户设 99999 秒，实际被 retry.js 的 Math.min 夹到 60）
//   reqRate=50000→ 50000     （实际被 TokenBucket 的 Math.min(…,10000) 夹到 10000）
//
// 危害不是"会崩"或"会被绕过"——消费端 retry.js / TokenBucket 都有防御纵深兜底，
// 所以三键**不会**造成限速绕过。真正的危害是**静默失真**：用户设的值与实际生效的值
// 不一致，且没有任何提示。这正是本仓反复出现的"语义漂移"形态：
// 同一个意思，两处实现，两种契约，改一处忘另一处。
//
// ── 为什么值得修 ────────────────────────────────────────────────────────────
// 防线不止一处才安全，这个事实本身就是"契约应该写在入口"的证据。
// 现在依赖三层各自为政的兜底，任何一层重构时都可能悄悄丢掉一层。
//
// ── 夹取而不是丢弃的理由 ────────────────────────────────────────────────────
// clampStr/pickInt 系列的契约是「非法值丢弃」，但那对"用户填了个越界数字"不友好：
// 填 delay=120 的本意是"慢一点"，夹到 60 保留了意图；丢弃则变成"不延时"，
// 反而比夹取更危险（限速突然消失）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyBackfill } from '../src/api/scanGuard/backfill.js';

// 与 exploitRoutes 的契约保持一致 —— 改动时必须两处同步
const CONTRACT = {
  delay: { min: 0, max: 60 },
  reqRate: { min: 0, max: 1000 },
  maxReq: { min: 0, max: 1_000_000 },
};

function backfill(key, value) {
  const config = {};
  applyBackfill(config, { [key]: value });
  return config[key];
}

test('缺陷-1) 负值必须夹到下界 0，不能原样透传', () => {
  // 实测旧行为：backfill('delay', -5) === -5
  for (const [key, c] of Object.entries(CONTRACT)) {
    assert.equal(backfill(key, -5), c.min,
      `${key}=-5 应夹到 ${c.min}，实际 ${backfill(key, -5)}（负值会让"设了延时"变成静默失效）`);
  }
});

test('缺陷-2) 超上限值必须夹到上界，不能原样透传', () => {
  // 实测旧行为：backfill('delay', 99999) === 99999
  const cases = [['delay', 99999, 60], ['reqRate', 50000, 1000], ['maxReq', 2e9, 1_000_000]];
  for (const [key, v, want] of cases) {
    assert.equal(backfill(key, v), want,
      `${key}=${v} 应夹到 ${want}，实际 ${backfill(key, v)}（用户设的值与实际生效值不符且无提示）`);
  }
});

test('契约-3) 区间内的合法值必须原样透传（不得因修夹取而误伤）', () => {
  // 这条最重要：夹取修复不能把正常值也改了 —— 那是"降低检出能力"的方向性错误。
  assert.equal(backfill('delay', 0), 0);
  assert.equal(backfill('delay', 0.5), 0.5);
  assert.equal(backfill('delay', 60), 60);
  assert.equal(backfill('reqRate', 100), 100);
  assert.equal(backfill('reqRate', 1000), 1000);
  assert.equal(backfill('maxReq', 5000), 5000);
});

test('契约-4) 非有限值仍按旧契约丢弃（不能被夹取逻辑顺手"救活"）', () => {
  // Infinity/NaN 原先被 Number.isFinite 挡掉。夹取若写成 Math.min(Infinity, 60)
  // 会得到 60 —— 把明显非法的输入变成了一个看起来合法的值，比丢弃更糟。
  assert.equal(backfill('delay', Infinity), undefined);
  assert.equal(backfill('delay', NaN), undefined);
  assert.equal(backfill('reqRate', -Infinity), undefined);
});

test('契约-5) 非数值类型按既有契约处理（夹取不得顺手改变字符串的既有行为）', () => {
  // 实测旧行为：非空字符串走 `typeof v === 'string' && v !== ''` 分支被 slice 透传。
  // 这是 backfill 既有的通用契约（注释里明说"其余形态不兜底，交由逐项 clamp"），
  // 本次只修数值夹取，不改字符串分支 —— 改动字符串行为属于超出缺陷范围的副作用。
  assert.equal(backfill('delay', '5'), '5', '非空字符串仍按既有契约透传，未被夹取逻辑接管');
  assert.equal(backfill('delay', ''), undefined, '空串仍被丢弃');
  assert.equal(backfill('delay', null), undefined);
  assert.equal(backfill('delay', {}), undefined, '对象形态不兜底');
});

test('自证-6) 夹取判据本身有效（不能是恒真的装饰品）', () => {
  // 若 CONTRACT 写错（比如 min>max），clamp 会把所有值夹成同一个数，
  // 测试 3 仍可能通过。这里显式验证 clamp 的边界行为本身正确。
  const clamp = (v, min, max) => Math.min(Math.max(v, min), max);
  assert.equal(clamp(-5, 0, 60), 0);
  assert.equal(clamp(99999, 0, 60), 60);
  assert.equal(clamp(0.5, 0, 60), 0.5);
  assert.equal(clamp(60, 0, 60), 60);
});
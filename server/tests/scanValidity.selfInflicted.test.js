// ============================================================================
// tests/scanValidity.selfInflicted.test.js —— 「自己把目标打报错」不得算成目标异常
// [P1-FIX 2026-09-08]
//
// 为什么单独成测：error 技术的工作方式就是让 DB 抛语法错，真实靶场（sqli-labs 风）里大半 payload
// 都回 500。若把这些 5xx 计入 serverErrRatio，「扫到了洞但满屏 500」会被裁定成 target_error，
// 于是每次正常扫描都弹「结论不可信」——告警疲劳一旦形成，真被封的时候没人看。
// 反过来也不能因此放过真正病恹恹的目标：良性请求（基线/探针之外）的 500 仍要判。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanValidityGuard, SQL_ERROR_SIG } from '../src/core/scanValidityGuard.js';

const INJ_REQ = { url: "http://t/?id=1' AND SLEEP(1)-- -", method: 'GET' };
const BENIGN_REQ = { url: 'http://t/?id=1', method: 'GET' };

test('SQL_ERROR_SIG 覆盖主流库报错形态（判据本身的回归）', () => {
  for (const s of [
    "You have an error in your SQL syntax near '1'",
    'syntax error at or near "1"',
    'ORA-00933: SQL command not properly ended',
    'SQLSTATE[42000]',
    'Unclosed quotation mark after the character string',
    'unrecognized token: ""1""',
  ]) {
    assert.ok(SQL_ERROR_SIG.test(s), `应命中 SQL 报错签名：${s}`);
  }
  for (const s of ['Internal Server Error', '500 — 网关超时，请稍后重试', '<h1>Bad Gateway</h1>']) {
    assert.ok(!SQL_ERROR_SIG.test(s), `不应命中：${s}`);
  }
});

test('注入请求引发的 500（含 SQL 报错签名）→ 状态保持 ok，不弹「结论不可信」', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 30; i++) {
    g.observe({
      req: INJ_REQ,
      res: { status: 500, data: "You have an error in your SQL syntax near '1''", headers: {} },
      error: null,
    });
  }
  const v = g.summary();
  assert.equal(v.status, 'ok', `自身触发的 SQL 报错不应裁定目标异常，实际：${v.status}`);
  assert.equal(v.reliable, true);
  assert.equal(v.counts.serverErr, 0);
  assert.equal(v.counts.injection5xx, 30, '但仍需在报告里可见：本次让目标报错了 30 次');
  assert.equal(g.shouldAbort, false);
});

test('良性请求的 500（无 SQL 签名）→ 仍判 target_error（不因精修而放过病态目标）', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 30; i++) {
    g.observe({ req: BENIGN_REQ, res: { status: 500, data: 'Service Unavailable', headers: {} }, error: null });
  }
  const v = g.summary();
  assert.equal(v.status, 'target_error');
  assert.equal(v.reliable, false);
  // counts 取「状态成立那一刻」的冻结快照（结论与数字同源，事后目标恢复不会把数字洗白），
  // 所以这里断言「>= 触发阈值」而不是「== 30」。
  assert.ok(v.counts.serverErr >= 10, `良性 5xx 应被计入，实际 ${v.counts.serverErr}`);
});

test('consumeBackoffMs：一次 Retry-After 只退避一次（取完即清），上限 30s', () => {
  const g = new ScanValidityGuard();
  g.observe({
    req: BENIGN_REQ,
    res: { status: 429, data: 'too many requests', headers: { 'retry-after': '5' } },
    error: null,
  });
  assert.equal(g.consumeBackoffMs(), 5000, '应把 Retry-After: 5 换算成 5000ms');
  assert.equal(g.consumeBackoffMs(), 0, '第二次取应为 0（否则多点位目标准成 N × 退避）');

  g.observe({
    req: BENIGN_REQ,
    res: { status: 503, data: 'slow down', headers: { 'retry-after': '600' } },
    error: null,
  });
  assert.equal(g.consumeBackoffMs(), 30000, '600s 必须被夹到 30s 上限（目标不能把扫描卡住）');
});

test('consumeBackoffMs：无拦截时无退避（零开销，行为与历史一致）', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 8; i++) {
    g.observe({ req: i % 2 ? INJ_REQ : BENIGN_REQ, res: { status: 200, data: '<h1>ok</h1>', headers: {} }, error: null });
  }
  assert.equal(g.consumeBackoffMs(), 0);
  assert.equal(g.summary().status, 'ok');
});

test('混合场景：注入 500（带签名）与良性 500 各半 → 只有后者参与裁定', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 20; i++) {
    g.observe({
      req: INJ_REQ,
      res: { status: 500, data: 'You have an error in your SQL syntax', headers: {} },
      error: null,
    });
    g.observe({ req: BENIGN_REQ, res: { status: 500, data: 'Database connection pool exhausted', headers: {} }, error: null });
  }
  const v = g.summary();
  assert.equal(v.counts.injection5xx, 20);
  assert.equal(v.counts.serverErr, 20);
  // 窗口内 40 个样本里只有良性那半（20/40）计入 5xx 比例，未过 0.8 阈值 → 保守不误判，但计数已留痕
  assert.equal(v.status, 'ok');
  assert.ok(v.counts.serverErr > 0, '良性 5xx 必须被计入计数（报告侧可提示人工关注）');
});

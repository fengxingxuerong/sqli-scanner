// ============================================================================
// server/tests/failureDetail.guard.test.js —— [D243] TAP 失败取证的判据自证
//
// 背景（D242 实测教训）：facts-sync 首轮红了一个用例、复跑绿。D225 的取证只打 `not ok` 行，
// 而那一行**只有用例名** —— 修那条 flaky 需要判据的输入量（maxGap / elapsed / reqs），
// 拿不到就只能盲调阈值。本守卫钉住「用例名 + 断言消息」能被成对取出。
//
// ⚠ 判据边界：只做**取证**，不改变任何判定。取不到 detail 时返回空串（不是抛错）。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractFailureDetails } from '../../scripts/lib/failureDetail.mjs';

test('§A not ok 行 + error 行：成对取出用例名与断言消息', () => {
  const tap = [
    'TAP version 13',
    'ok 1 - 通过的用例 (1.2ms)',
    'not ok 2 - ★修复①★ 慢漂移 + 极小余量',
    '  ---',
    '  duration_ms: 8613.65',
    "  error: 'AssertionError [ERR_ASSERTION]: 本抽无环境越界证据：maxGap=52ms ≤ 150ms、elapsed=8000ms ≤ 20000ms'",
    "  expected: '5.7.40'",
    "  actual: '5/7.40'",
    '  ...',
    '# fail 1',
  ].join('\n');
  const got = extractFailureDetails(tap);
  assert.equal(got.length, 1);
  assert.match(got[0].title, /修复①/);
  assert.match(got[0].detail, /maxGap=52ms/);
  assert.match(got[0].detail, /elapsed=8000ms/);
});

test('§B 全绿输出：返回空数组（取证不该制造噪音）', () => {
  const tap = ['TAP version 13', 'ok 1 - 用例 (1ms)', '# fail 0'].join('\n');
  assert.deepEqual(extractFailureDetails(tap), []);
  assert.deepEqual(extractFailureDetails(''), []);
  assert.deepEqual(extractFailureDetails(undefined), []);
});

test('§C error 行缺席：只给用例名，detail 为空串（不抛错、不猜）', () => {
  const tap = ['not ok 3 - 某个用例', '  ---', '  duration_ms: 12.3', '  ...', '# fail 1'].join('\n');
  const got = extractFailureDetails(tap);
  assert.equal(got.length, 1);
  assert.equal(got[0].detail, '');
});

test('§D error 行离 not ok 太远（>20 行窗口）：不得串到后一个用例的 error', () => {
  const filler = Array.from({ length: 25 }, (_, i) => `  duration_ms: ${i}.0`);
  const tap = [
    'not ok 4 - 前一个用例',
    ...filler,
    "  error: '这是前一个用例自己的 error'",
    'not ok 5 - 后一个用例',
    "  error: '这是后一个用例自己的 error'",
  ].join('\n');
  const got = extractFailureDetails(tap);
  assert.equal(got.length, 2);
  // 前一个用例的 error 在 20 行窗口之外 ⇒ detail 取不到（宁可空着，也不误取别人的）
  assert.equal(got[0].detail, '');
  assert.match(got[1].detail, /后一个用例自己的/);
});

test('§E 多条失败按出现顺序取，limit 生效', () => {
  const mk = (i) => [
    `not ok ${i} - 用例${i}`,
    '  ---',
    `  error: '断言消息${i}'`,
  ].join('\n');
  const tap = [mk(1), mk(2), mk(3)].join('\n');
  const got = extractFailureDetails(tap, 2);
  assert.equal(got.length, 2);
  assert.match(got[0].detail, /断言消息1/);
  assert.match(got[1].detail, /断言消息2/);
});

test('§F 断言消息含冒号/引号/等号：原样取出不被截断在首个冒号', () => {
  const tap = [
    'not ok 6 - 用例',
    "  error: 'AssertionError: 实际 \"5/7.40\" !== \"5.7.40\"（maxGap=52ms）'",
  ].join('\n');
  const got = extractFailureDetails(tap);
  assert.match(got[0].detail, /5\/7\.40/);
  assert.match(got[0].detail, /maxGap=52ms/);
});

// [D210] 闭合前缀探测的 OR 兜底：空基线目标上 AND 差分恒无信号，只有 OR 能区分。
//
// 真机证据（demo.testfire.net POST /doLogin，testuser 不是有效用户）：
//   testuser' AND 1=1-- -  → login.jsp    | testuser' AND 1=2-- -  → login.jsp   （无差异）
//   testuser' OR  1=1-- -  → bank/main.jsp | testuser' OR  1=2-- -  → login.jsp   （有差异）
// 修复前 _boundaryPairDiff 只试 AND ⇒ 该点 boundary='' ⇒ union/提取拿不到闭合前缀。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { createTarget } from '../src/engine/models.js';

const ORIG = 'testuser';
const LOGIN_FAIL = '<html><body>Login Failed: username or password not found</body></html>';
const LOGIN_OK = '<html><body>Welcome to Altoro Mutual (bank main)</body></html>';

/**
 * 模拟「原值查不到行 + 只有带引号闭合的 OR 恒真才改变页面」的目标。
 * AND 族一律落登录失败页（`WHERE uid='ghost' AND 1=1` 仍是空集）。
 * @returns {object} 带 request 的假 httpClient
 */
function makeEmptyBaselineTarget() {
  return {
    async request(opts) {
      const u = new URL(opts.url);
      const v = u.searchParams.get('uid') ?? '';
      // 只有「单引号闭合 + OR 1=1」才会登录成功；其余（含未闭合的 OR）都是失败页
      const closed = v.startsWith(`${ORIG}'`) || v.startsWith(`${ORIG}"`);
      const orTrue = /\bOR\s+1=1--/.test(v);
      return { status: 200, headers: {}, data: closed && orTrue ? LOGIN_OK : LOGIN_FAIL };
    },
  };
}

/** @returns {{httpClient: object, target: object, point: object, config: object}} 探测上下文 */
function makeCtx() {
  return {
    httpClient: makeEmptyBaselineTarget(),
    target: createTarget({ url: 'http://mock/doLogin?uid=testuser', method: 'GET' }),
    point: { id: 'p1', location: 'url', param: 'uid', originalValue: ORIG },
    config: {},
  };
}

test('[D210] 空基线目标：AND 差分无信号时，OR 兜底必须探出闭合前缀', async () => {
  const det = new Detector('union');
  const boundary = await det.probeBoundary(makeCtx());
  assert.ok(
    boundary === "'" || boundary === '"',
    `应探出闭合前缀，实得 ${JSON.stringify(boundary)}（空串 = OR 兜底没生效，该点 union/提取全灭）`,
  );
});

test('[D210] 反向守卫：参数化目标（任何输入同一页）不得被 OR 兜底误报成有闭合前缀', async () => {
  const flat = {
    async request() {
      return { status: 200, headers: {}, data: '<html>static login page, nothing changes</html>' };
    },
  };
  const det = new Detector('union');
  const ctx = { ...makeCtx(), httpClient: flat };
  const boundary = await det.probeBoundary(ctx);
  assert.equal(boundary, '', '所有输入同页 ⇒ 无闭合信号 ⇒ 必须回退空串');
});

// [D210-已知缺陷钉] 「真正闭合的候选被丢弃」：候选 `'` 的 `AND 1=1` 已经改变了页面 ⇒ 判「不相似」
// ⇒ 不进 similarHits ⇒ OR 复核只针对「AND 无变化」的那批（必然全失败）⇒ 最终回退首个候选（通常 `''`）。
// 修复方向（offBaseline 候选做差分）曾实现并验证能让本目标探出 `'`，但会放大 error 通道假阳
//（boundary 非空 ⇒ 所有点 error 探针带 `'`；btnSubmit 实测返回正常页却被判 error）⇒ 已回滚，
// 待 error 侧「payload 引起 vs 引号引起」判据补上再启用（TODO D211）。
// 本用例钉住**当前**行为：一旦有人修复，这里会红，提醒同步更新而不是静默改变结论。
test('[D210-已知缺陷] AND 能区分的常规目标：当前仍回退空串（修复后本用例应变红并更新）', async () => {
  const normal = {
    async request(opts) {
      const u = new URL(opts.url);
      const v = u.searchParams.get('uid') ?? '';
      // 常规目标：带引号闭合后 AND 1=1 命中、AND 1=2 不命中
      const closed = v.startsWith(`${ORIG}'`);
      const andTrue = /\bAND\s+1=1--/.test(v);
      return { status: 200, headers: {}, data: closed && andTrue ? LOGIN_OK : LOGIN_FAIL };
    },
  };
  const det = new Detector('union');
  const ctx = { ...makeCtx(), httpClient: normal };
  const boundary = await det.probeBoundary(ctx);
  assert.equal(boundary, '', '当前行为=空串（缺陷未修）；若已修复，请把本用例改成断言 "\'" 并更新 D210 记录');
});

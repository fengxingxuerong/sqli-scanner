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

// ============================================================================
// [D225 2026-11-01] OR 兜底的「假通过」阴影：低保真前缀不得抢在正确前缀之前胜出
//
// 真机回归证据（OWASP Juice Shop 20.3.0 `/rest/products/search?q=`，SQLite，外部裁判
// 真值端点 2/2 → 1/2 后二分定位 + 逐请求取证）：
//   · 候选表 `'))` 排在 `%'))` 之前；错误层级的 `'))` 在 OR 对上差分巨大
//     （`apple')) OR 1=1-- -` → 全表 34245B vs `OR 1=2` → 空集 30B）⇒ D210 兜底让它提前返回，
//     正确前缀 `%'))`（AND 对：apple 行 ≈ 基线 1617B）所在的第二波根本没跑；
//   · boundary=`'))` 后布尔真侧偏离基线被拒、error 被归因对照拒 ⇒ 全通道静默漏检。
// 单探针阶段为何全落空（PAIR-FIX 同源）：基线与候选以**不同口径**剥回显（基线剥 orig、
// 候选剥完整 payload），注入值恰好也是 legit 内容时（`apple_juice.jpg`）削量不对称
//（实测同一份 1617B 响应基线侧被削 75B、候选侧 0B）⇒ 完美复现基线的候选判「不相似」。
//
// mock 复刻该形态：基线页里含 `testuser` 字样的 legit 内容（图名 `testuser_pic.jpg`），
// 使基线剥 orig 后与候选剥 payload 后不对称 ⇒ similarHits=0 强制走进 pairDiff。
// ============================================================================

const ROWS = '<html>results: <img src="testuser_pic.jpg"> row(testuser, 1) row(testuser, 2)</html>';
const ALL_ROWS = '<html>results: EVERY ROW user-a user-b user-c user-d user-e user-f testuser row</html>';
const EMPTY = '<html>results: (none)</html>';
const SQL_ERR = '<html>SQLITE_ERROR: syntax error</html>';

/** LIKE 上下文：`%'))` 是唯一 AND-oracle 前缀；`'))` 只在 OR 上「假通过」（OR 1=1 全表） */
function makeLikeContextTarget() {
  return {
    async request(opts) {
      const u = new URL(opts.url);
      const v = u.searchParams.get('uid') ?? '';
      if (v === ORIG) return { status: 200, headers: {}, data: ROWS };
      if (v.startsWith(`${ORIG}%'))`)) {
        if (/\bAND\s+1=1--/.test(v)) return { status: 200, headers: {}, data: ROWS };
        if (/\bOR\s+1=1--/.test(v)) return { status: 200, headers: {}, data: ROWS };
        return { status: 200, headers: {}, data: EMPTY };
      }
      if (v.startsWith(`${ORIG}'))`)) {
        if (/\bOR\s+1=1--/.test(v)) return { status: 200, headers: {}, data: ALL_ROWS };
        return { status: 200, headers: {}, data: EMPTY };
      }
      if (v.startsWith(`${ORIG}'`)) return { status: 500, headers: {}, data: SQL_ERR };
      return { status: 200, headers: {}, data: EMPTY };
    },
  };
}

test('[D225] OR 兜底的假通过阴影：低保真前缀不得抢在锚定基线的正确前缀之前', async () => {
  const det = new Detector('union');
  const ctx = { ...makeCtx(), httpClient: makeLikeContextTarget() };
  const boundary = await det.probeBoundary(ctx);
  assert.equal(
    boundary,
    `%'))`,
    `应探出锚定基线的正确前缀 %'))，实得 ${JSON.stringify(boundary)}` +
      `（='))' 即假通过阴影复发：OR 全表差分抢跑，该点 union/boolean 全通道静默）`,
  );
});

test('[D225] 无锚定可用时（两侧都偏离基线）兜底仍返回首个差分前缀，锚定不得是硬门槛', async () => {
  // PAIR-FIX 类目标的形态：真侧是「比基线更大的行集」（不 ≈ 基线）、假侧空集（也不 ≈ 基线），
  // 且基线含 orig 形态的 legit 内容使单探针阶段全落空。此时没有任何候选能锚定，
  // 行为必须与修复前一致：取首个差分命中（否则该类目标的闭合探测全军覆没）。
  const blowupEcho = {
    async request(opts) {
      const u = new URL(opts.url);
      const v = u.searchParams.get('uid') ?? '';
      const closed = v.startsWith(`${ORIG}'`);
      const andTrue = /\bAND\s+1=1--/.test(v);
      // 闭合后的「真」侧 = 比基线更大的行集（不 ≈ 基线）；闭合假侧 = 空集（也不 ≈ 基线）；
      // 未闭合（含基线）= 与基线同页。echo 把 payload 原样打回 ⇒ 锚定必然失败。
      const results = closed && andTrue ? ALL_ROWS : closed ? EMPTY : ROWS;
      return { status: 200, headers: {}, data: `<html>debug-sql=[${v}] results: ${results}</html>` };
    },
  };
  const det = new Detector('union');
  const ctx = { ...makeCtx(), httpClient: blowupEcho };
  const boundary = await det.probeBoundary(ctx);
  assert.equal(
    boundary,
    `'`,
    `无锚定候选时应回退首个差分前缀 '，实得 ${JSON.stringify(boundary)}（空串 = 兜底丢失，回显型目标闭合探测报废）`,
  );
});

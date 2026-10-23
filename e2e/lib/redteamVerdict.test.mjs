// ============================================================================
// redteamVerdict.test.mjs —— [D134] 红队判定的判据自证
//
// 用例直接对应 2026-10-23 实测的事故：env.mjs 自己拉起的 mysqld 口令未知 →
// 靶场库不可用 → 19 个真值点全漏 → 门禁把「环境缺失」记成「检出率 0% FAIL」。
// 判定必须能把它认成 blocked（缺依赖），而不是 fail（能力退化）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyRedteamOutput } from './redteamVerdict.mjs';

test('全中且零误报 ⇒ pass（只吃事实数字，不看套件自报的 PASS 字样）', () => {
  const out = '[redteam] round=r2 vuln=19 hit=19 rate=100% safe=7 fp=0\n[PASS] 红队实战评测';
  const v = classifyRedteamOutput(out);
  assert.equal(v.status, 'pass');
  assert.equal(v.facts['检出'], '19/19');
  assert.equal(v.facts['误报'], '0');
  assert.equal(v.reason, null);
});

test('漏一个 ⇒ fail（D92：必须全中，不许阈值容错）', () => {
  const v = classifyRedteamOutput('[redteam] round=r2 vuln=19 hit=18 rate=95% safe=7 fp=0');
  assert.equal(v.status, 'fail');
  assert.match(v.reason, /漏检 1\/19/);
});

test('安全点误报 ⇒ fail（误报优先于漏检报出）', () => {
  const v = classifyRedteamOutput('[redteam] round=r2 vuln=19 hit=19 rate=100% safe=7 fp=1');
  assert.equal(v.status, 'fail');
  assert.match(v.reason, /安全点误报 1 个/);
});

test('靶场库不可用（[BLOCKED] 且没有 round 行）⇒ blocked，不记成能力退化', () => {
  const out = '[env] MySQL 已在运行，复用\n[BLOCKED] 靶场库不可用：root 口令探测全部失败（候选 root/空）';
  const v = classifyRedteamOutput(out);
  assert.equal(v.status, 'blocked');
  assert.match(v.reason, /口令探测全部失败/);
  assert.equal(v.facts['靶场库'], '不可用');
});

test('自起失败（[SKIP] 且没有 round 行）⇒ skip，不算通过也不算失败', () => {
  const v = classifyRedteamOutput('[SKIP] 自起红队靶场失败（120s 内 8231 未就绪，多半是缺 PostgreSQL）');
  assert.equal(v.status, 'skip');
  assert.match(v.reason, /8231 未就绪/);
});

test('[BLOCKED] 出现在旁支日志但 round 行存在 ⇒ 仍按事实判定（不得借跳过逃逸）', () => {
  const out = '[BLOCKED] 某可选依赖缺失\n[redteam] round=r2 vuln=19 hit=19 rate=100% safe=7 fp=0';
  assert.equal(classifyRedteamOutput(out).status, 'pass');
  const out2 = '[BLOCKED] 某可选依赖缺失\n[redteam] round=r2 vuln=19 hit=0 rate=0% safe=7 fp=0';
  assert.equal(classifyRedteamOutput(out2).status, 'fail', '跑了就必须按事实判，不能因旁支 BLOCKED 变跳过');
});

test('取不到 round 数字 ⇒ fail 且写明是判据失效（门禁自己坏了不许静默通过）', () => {
  const v = classifyRedteamOutput('gate-check 崩了，没有任何汇总行');
  assert.equal(v.status, 'fail');
  assert.match(v.reason, /未取到 gate-check 判据/);
});

test('真值分母为 0 ⇒ fail（真值表空 = 判据失效，不是"零漏检"）', () => {
  const v = classifyRedteamOutput('[redteam] round=r2 vuln=0 hit=0 rate=0% safe=0 fp=0');
  assert.equal(v.status, 'fail');
  assert.match(v.reason, /真值分母为 0/);
});
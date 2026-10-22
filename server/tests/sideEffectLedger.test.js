// ============================================================================
// sideEffectLedger.test.js —— [D90 2026-10-18] 写副作用登记与自动清理（P2-5）
//
// 缺口原文（TODO 2026-10-10）：「写副作用无自动清理/回滚（只有
// docs/pentest-handover/05 的人工条款 R5/R6）」——人工条款要求「记录全部副作用并清理」，
// 但代码里**没有对应物**：fileWrite 往客户服务器落的文件、os-shell 起的进程，
// 事后既无清单也无收尾动作。本模块补这一层。
//
// 判据设计（每条都对应一个真实误用场景）：
//   · 登记：写前登记（失败也留痕）——「试过但没记」比「记了失败」危险
//   · 可逆性分档：fileWrite 可删、os-shell 不可保证收回（如实标注，不假装能清）
//   · 清理幂等：已清理项不再入计划（重复执行不产生第二次写）
//   · 失败不静默：清理失败必须逐条回报（客户要知道哪个残留没清掉）
//   · fail-closed：登记表损坏时返回空壳但**显式告警**，不静默当无事
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// 台账根目录可经环境变量重定向（仓库既有能力），测试隔离到临时目录
const TMP = mkdtempSync(join(tmpdir(), 'se-test-'));
// 台账根目录的 env 名是 SQLI_LEDGER_DIR（见 scanLedger.js:22）；写错名会导致
// 测试把登记表写进真实 data/ledger ⇒ 用例间互相污染（实测「2 !== 1」即此因）
process.env.SQLI_LEDGER_DIR = TMP;

const {
  SIDE_EFFECT_KINDS,
  recordSideEffect,
  readSideEffects,
  buildCleanupPlan,
  cleanupSideEffects,
  sideEffectSummaryForReport,
} = await import('../src/services/sideEffectLedger.js');

test('登记：写前记录并落盘，含可逆性与撤销配方', () => {
  const scanId = 'se-1';
  recordSideEffect(scanId, {
    kind: SIDE_EFFECT_KINDS.FILE_WRITE,
    target: '/var/www/shell.php',
    detail: '写入 120 字节',
    undo: 'rm -f -- /var/www/shell.php',
  });
  const store = readSideEffects(scanId);
  assert.equal(store.effects.length, 1);
  const e = store.effects[0];
  assert.equal(e.kind, 'file_write');
  assert.equal(e.target, '/var/www/shell.php');
  assert.equal(e.status, 'applied');
  assert.equal(e.reversible, true, 'file_write 默认可逆（删文件）');
  assert.ok(existsSync(join(TMP, scanId, 'side-effects.json')), '登记表必须落盘');
});

test('登记：写失败也留痕（status=failed），不静默丢弃', () => {
  const scanId = 'se-fail';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/x/y' }, 'permission denied');
  const store = readSideEffects(scanId);
  assert.equal(store.effects.length, 1);
  assert.equal(store.effects[0].status, 'failed');
  assert.match(store.effects[0].error, /permission denied/);
});

test('可逆性分档：os-shell 标不可逆，stacked DML 仅在给了反向语句时可逆', () => {
  const scanId = 'se-kind';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.OS_SHELL, target: 'whoami' });
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.STACKED_DML, target: 'users' });
  recordSideEffect(scanId, {
    kind: SIDE_EFFECT_KINDS.STACKED_DML, target: 'orders',
    undo: "DELETE FROM orders WHERE id=999",
  });
  const store = readSideEffects(scanId);
  const byTarget = Object.fromEntries(store.effects.map((e) => [e.target, e]));
  assert.equal(byTarget.whoami.reversible, false, 'os-shell 不假装可收回');
  assert.equal(byTarget.users.reversible, 'undo-only');
  assert.equal(byTarget.orders.reversible, 'undo-only');
});

test('清理计划：可逆项入计划、不可逆项单列（不混进可清理数里）', () => {
  const scanId = 'se-plan';
  recordSideEffect(scanId, {
    kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/a', undo: 'rm -f -- /tmp/a',
  });
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.OS_SHELL, target: 'id' });
  const plan = buildCleanupPlan(scanId);
  assert.equal(plan.items.length, 1);
  assert.equal(plan.irreversible.length, 1);
  assert.deepEqual(plan.summary, { 应清理: 1, 不可逆: 1, 总计: 2, 已清理: 0 });
});

test('默认撤销配方：无显式 undo 时按类型给出保守形态', () => {
  const scanId = 'se-default';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/b' });
  const plan = buildCleanupPlan(scanId);
  assert.equal(plan.items.length, 1);
  assert.match(plan.items[0].undo, /^rm -f -- \/tmp\/b$/);
});

test('执行清理：成功项标记 cleaned 并回写；幂等——再跑计划为空', async () => {
  const scanId = 'se-clean';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/c', undo: 'rm -f -- /tmp/c' });
  const calls = [];
  const executor = async (cmd) => { calls.push(cmd); return { ok: true, output: '' }; };

  const r1 = await cleanupSideEffects(scanId, executor);
  assert.equal(r1.summary.已清理, 1);
  assert.equal(r1.summary.失败, 0);
  assert.deepEqual(calls, ['rm -f -- /tmp/c']);

  const store = readSideEffects(scanId);
  assert.ok(store.effects[0].cleanedAt, '清理时间必须回写');
  // 幂等：第二次不再执行同一撤销
  const r2 = await cleanupSideEffects(scanId, executor);
  assert.equal(r2.summary.已清理, 0);
  assert.equal(calls.length, 1, '已清理项不得重复执行（否则等于又动一次目标）');
});

test('失败不静默：执行器报错时逐条回报 failed，且不标记 cleaned', async () => {
  const scanId = 'se-clean-fail';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/d', undo: 'rm -f -- /tmp/d' });
  const r = await cleanupSideEffects(scanId, async () => ({ ok: false, error: '目标不可达' }));
  assert.equal(r.summary.失败, 1);
  const row = r.results.find((x) => x.status === 'failed');
  assert.match(row.error, /目标不可达/);
  assert.equal(readSideEffects(scanId).effects[0].cleanedAt, null, '失败不得标记为已清理');
});

test('执行器抛异常同样计入失败（不能中断整个清理流程）', async () => {
  const scanId = 'se-throw';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/e', undo: 'rm -f -- /tmp/e' });
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/f', undo: 'rm -f -- /tmp/f' });
  let n = 0;
  const r = await cleanupSideEffects(scanId, async () => {
    n += 1;
    if (n === 1) throw new Error('boom');
    return { ok: true };
  });
  assert.equal(n, 2, '第一条抛异常不得阻断第二条');
  assert.equal(r.summary.失败, 1);
  assert.equal(r.summary.已清理, 1);
});

test('报告摘要：无副作用返回 null；有则给出「写了什么/清没清」的可核对面', () => {
  assert.equal(sideEffectSummaryForReport('se-empty'), null);
  const scanId = 'se-report';
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/g' });
  recordSideEffect(scanId, { kind: SIDE_EFFECT_KINDS.OS_SHELL, target: 'id' });
  const s = sideEffectSummaryForReport(scanId);
  assert.equal(s.总数, 2);
  assert.equal(s.待清理, 1);
  assert.equal(s.不可逆, 1);
  assert.equal(s.明细.length, 2);
});

test('登记表损坏：返回空壳 + corrupt 标记，不抛（且不静默）', () => {
  const scanId = 'se-corrupt';
  const dir = join(TMP, scanId);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'side-effects.json'), '{ this is not json', 'utf8');
  const store = readSideEffects(scanId);
  assert.deepEqual(store.effects, []);
  assert.equal(store.corrupt, true, '损坏必须显式标记，便于人工核查');
});

// ── [D132 2026-10-23] 路径穿越：scanId 只许作单层目录名 ──────────────────────
// 背景：旧实现 `join(ledgerRoot(), String(scanId), 'side-effects.json')` 未校验，而 scanId
// 来自 REST 查询串/请求体 ⇒ `../../x` 可越界读写任意位置名为 side-effects.json 的文件，
// 且清理路径会在该位置递归建目录。scanLedger 早有 safeScanId，这里漏了同一道判据。
test('路径穿越：readSideEffects 对 ../ 越界 scanId 必须拒绝（不得读到根外文件）', () => {
  const evil = '../' + 'escape-probe';
  assert.throws(
    () => readSideEffects(evil),
    (e) => e && e.code === 1005,
    '含 ../ 的 scanId 必须抛 SCAN_ID_INVALID，而不是拼进路径'
  );
  // 变体逐条钉死：Windows/POSIX 分隔符、绝对路径、NUL、当前/父目录
  for (const bad of ['..', '.', 'a/b', 'a\\b', '/etc', 'C:\\temp', 'x\0y', '']) {
    assert.throws(() => readSideEffects(bad), (e) => e && e.code === 1005, `scanId=${JSON.stringify(bad)} 必须拒绝`);
  }
});

test('路径穿越：recordSideEffect / buildCleanupPlan 同口径拒绝（写与清理都不得越界）', () => {
  assert.throws(
    () => recordSideEffect('../../pwn', { kind: SIDE_EFFECT_KINDS.FILE_WRITE, target: '/tmp/x' }),
    (e) => e && e.code === 1005
  );
  assert.throws(() => buildCleanupPlan('../..'), (e) => e && e.code === 1005);
  assert.throws(() => sideEffectSummaryForReport('a/b'), (e) => e && e.code === 1005);
});

// 收尾：清测试用临时台账目录（仅本测试自己创建的）
process.on('exit', () => {
  try { rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ }
});

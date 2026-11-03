// ============================================================================
// tests/cli.cleanup.test.js —— [D198] 利用后清理（对标 sqlmap --cleanup）与 --purge
//
// 判据从行为出发（与 cli.registryOp.test.js 同形态，零网络）：
//   · 写前登记：udfInstall / registryWrite 现在必须留痕（此前只有 fileWrite 登记 ——
//     P1 缺口的根因正是「台账里没有可清理的项」）；
//   · 通道路由：SQL 类撤销（udf_install 的 DROP）必须走 sql-shell，文件/注册表走
//     os-shell（旧 REST 清理把 DROP FUNCTION 发给 os-shell = 潜伏 bug，已修）；
//   · 门：--cleanup 与利用动作同门（EXPLOIT_ENABLED + --authorized + 注入点）；
//   · purge：非交互必须 --yes；--yes 后台账目录删除（targets 注入缝，不碰真实日志）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Exploiter } from '../src/engine/Exploiter.js';
import { recordSideEffect, readSideEffects } from '../src/services/sideEffectLedger.js';

const { runPostScanActions, runPurge, buildConfig } = await import('../bin/cli.js');
const { parseArgs } = await import('../bin/cli/args.js');

// 台账根目录指向临时目录（ledgerRoot() 读 SQLI_LEDGER_DIR）——模块加载期生效，必须先设
const LEDGER_TMP = mkdtempSync(join(tmpdir(), 'cleanup-ledger-'));
process.env.SQLI_LEDGER_DIR = LEDGER_TMP;

async function capture(fn) {
  const err = [];
  const out = [];
  const oe = console.error;
  const ol = console.log;
  console.error = (...a) => err.push(a.join(' '));
  console.log = (...a) => out.push(a.join(' '));
  try {
    return { ret: await fn(), err: err.join('\n'), out: out.join('\n') };
  } finally {
    console.error = oe;
    console.log = ol;
  }
}

/** patch Exploiter 原型三个通道，记录调用 */
function patchChannels() {
  const calls = { os: [], sql: [] };
  const orig = { os: Exploiter.prototype.osShell, sql: Exploiter.prototype.sqlShell };
  Exploiter.prototype.osShell = async (ctx, cmd) => { calls.os.push(cmd); return { ok: true, raw: `ran:${cmd}` }; };
  Exploiter.prototype.sqlShell = async (ctx, sql) => { calls.sql.push(sql); return { ok: true, value: `executed:${sql}` }; };
  return { calls, restore: () => { Exploiter.prototype.osShell = orig.os; Exploiter.prototype.sqlShell = orig.sql; } };
}

function withFlagEnv(enabled, authorized, fn) {
  const prev = process.env.EXPLOIT_ENABLED;
  if (enabled) process.env.EXPLOIT_ENABLED = '1';
  else delete process.env.EXPLOIT_ENABLED;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.EXPLOIT_ENABLED;
    else process.env.EXPLOIT_ENABLED = prev;
  });
}

const REPORT = {
  scanId: 'scan-cleanup-test',
  vulns: [{ pointId: 'p1', dbms: 'SQL Server' }],
  points: [{ id: 'p1', originalValue: '1', location: 'url', param: 'q' }],
  target: {},
  dbms: 'SQL Server',
};

test('args：--cleanup 被消费且不落 unknownFlags（布尔语义）', () => {
  const a = parseArgs(['-u', 'http://127.0.0.1:9/x', '--cleanup']);
  assert.deepEqual(a.unknownFlags, []);
  assert.equal(a.cleanup, true);
});

test('args/config：--cleanup 带值 → 明确拒绝（不静默忽略，收参数不生效是红线）', () => {
  const a = parseArgs(['-u', 'http://127.0.0.1:9/x', '--cleanup', 'scan-123']);
  assert.equal(a.cleanup, 'scan-123');
  assert.throws(() => buildConfig(a), /--cleanup 不接受值/);
});

test('写前登记：registryWrite 留 reg_write（target = hive\\key\\value，撤销带 /v + /f）', async () => {
  const sent = [];
  const extractor = {
    async _send(_ctx, sql) { sent.push(sql); return { status: 200, data: '' }; },
    async _guessColumnsCached() { return 2; },
    async extractScalar() { return null; },
  };
  const ex = new Exploiter(extractor);
  await ex.registryWrite({ dbms: 'SQL Server', scanId: 'scan-reg-rec', point: { originalValue: '1' } }, {
    key: 'SOFTWARE\\x', value: 'v', data: 'd',
  });
  const store = readSideEffects('scan-reg-rec');
  const rows = store.effects.filter((e) => e.kind === 'reg_write');
  assert.equal(rows.length, 1);
  assert.match(rows[0].target, /HKEY_LOCAL_MACHINE\\\\?SOFTWARE\\\\?x\\\\?v/);
  // [D250] 撤销配方必须把「键」与「/v 值名」拆开：defaultUndo 会把 target 整体当键路径
  // （reg delete "hive\key\value" 删的是不存在的键），清理必失败且会被当成「目标已清」。
  assert.equal(rows[0].undo, 'reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\x" /v "v" /f');
  assert.match(rows[0].undo, / \/f$/);
  assert.match(sent[0], /xp_regwrite/);
});

test('写前登记：udfInstall 全链留 file_write（平台化撤销）+ udf_install ×2（DROP 撤销）', async () => {
  const hexPath = join(LEDGER_TMP, 'udf.hex');
  // 清洗后需 ≥64 位且偶数位（真实库合理性校验）；不能带 0x 前缀（'0' 保留会让位数奇偶不可控）
  writeFileSync(hexPath, 'ab'.repeat(64));
  const extractor = {
    async _send() { return { status: 200, data: '' }; },
    async _guessColumnsCached() { return 2; },
    async extractScalar(_ctx, sql) {
      if (/plugin_dir/.test(sql)) return '/usr/lib/mysql/plugin/';
      return 'null';
    },
  };
  const ex = new Exploiter(extractor);
  const r = await ex.udfInstall({ dbms: 'MySQL', scanId: 'scan-udf-rec', point: { originalValue: '1' } }, {
    hexPath, platform: 'linux',
  });
  assert.equal(r.ok, true);
  const store = readSideEffects('scan-udf-rec');
  const files = store.effects.filter((e) => e.kind === 'file_write');
  const fns = store.effects.filter((e) => e.kind === 'udf_install');
  assert.equal(files.length, 1);
  assert.match(files[0].target, /\/usr\/lib\/mysql\/plugin\/lib_mysqludf_sys\.so$/);
  assert.match(files[0].undo, /^rm -f -- /);
  assert.deepEqual(fns.map((f) => f.target).sort(), ['sys_eval', 'sys_exec']);
  for (const f of fns) assert.match(f.undo, /^DROP FUNCTION IF EXISTS /);
});

test('路由：cleanup 把 SQL 类撤销走 sql-shell、文件/注册表走 os-shell', async () => {
  // 与 REPORT.scanId 同账：登记错 scanId = 清理看不到（本测试自己先踩过这个坑）
  recordSideEffect('scan-cleanup-test', { kind: 'file_write', target: '/tmp/x', undo: 'rm -f -- /tmp/x' });
  recordSideEffect('scan-cleanup-test', { kind: 'udf_install', target: 'sys_eval', undo: 'DROP FUNCTION IF EXISTS sys_eval' });
  await withFlagEnv(true, true, async () => {
    const p = patchChannels();
    try {
      const { ret } = await capture(() => runPostScanActions(REPORT, { authorized: true, cleanup: true }));
      assert.equal(ret && ret.ok !== undefined ? ret.ok : true, true);
      assert.ok(p.calls.os.includes('rm -f -- /tmp/x'), `os-shell 应收到文件撤销：${JSON.stringify(p.calls.os)}`);
      assert.ok(p.calls.sql.includes('DROP FUNCTION IF EXISTS sys_eval'), `sql-shell 应收到 DROP：${JSON.stringify(p.calls.sql)}`);
    } finally {
      p.restore();
    }
  });
});

test('门：--cleanup 未开 EXPLOIT_ENABLED / 未 --authorized → 拒绝且零调用', async () => {
  const p = patchChannels();
  try {
    await withFlagEnv(false, true, async () => {
      const { ret, err } = await capture(() => runPostScanActions(REPORT, { authorized: true, cleanup: true }));
      assert.equal(ret, null);
      assert.match(err, /利用操作未启用/);
    });
    await withFlagEnv(true, false, async () => {
      const { err } = await capture(() => runPostScanActions(REPORT, { cleanup: true }));
      assert.match(err, /--authorized/);
    });
    assert.equal(p.calls.os.length + p.calls.sql.length, 0);
  } finally {
    p.restore();
  }
});

test('空台账：cleanup 如实说明无登记项（不假装清了什么）', async () => {
  await withFlagEnv(true, true, async () => {
    const p = patchChannels();
    try {
      const { ret } = await capture(() => runPostScanActions({ ...REPORT, scanId: 'scan-no-effects' }, { authorized: true, cleanup: true }));
      assert.match(JSON.stringify(ret), /无已登记的写副作用/);
      assert.equal(p.calls.os.length + p.calls.sql.length, 0);
    } finally {
      p.restore();
    }
  });
});

test('purge：非交互无 --yes → 拒绝（退出码 2）；--yes → 台账目录删除（targets 注入缝）', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'purge-target-'));
  mkdirSync(join(dir, 'sub'), { recursive: true });
  writeFileSync(join(dir, 'side-effects.json'), '{}');
  const file = join(dir, 'a.log');
  writeFileSync(file, 'log');
  const code1 = await runPurge(['--purge'], { targets: [{ label: '注入目录', path: dir, dir: true }] });
  assert.equal(code1, 2, '非交互无 --yes 必须拒绝');
  assert.ok(existsSync(dir), '拒绝时不得删除');
  const code2 = await runPurge(['--purge', '--yes'], { targets: [{ label: '注入目录', path: dir, dir: true }] });
  assert.equal(code2, 0);
  assert.equal(existsSync(dir), false, '--yes 后目录应删除');
  assert.equal(existsSync(file), false);
  // 清理本测试在真实台账目录里可能留下的空壳（readSideEffects 只在读取时构造，不落盘）
});

test('purge：best-effort 目标失败不阻断（文件被占用/不存在的形态）', async () => {
  const ghost = join(tmpdir(), `purge-ghost-${Date.now()}`);
  const code = await runPurge(['--purge', '--yes'], {
    targets: [
      { label: '不存在（跳过）', path: ghost },
      { label: '注入目录', path: mkdtempSync(join(tmpdir(), 'purge-ok-')), dir: true },
    ],
  });
  assert.equal(code, 0);
});

test('收尾：清理临时台账目录', () => {
  rmSync(LEDGER_TMP, { recursive: true, force: true });
  assert.ok(true);
});

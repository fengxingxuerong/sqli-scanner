// ============================================================================
// server/tests/cli.directScope.test.js —— CLI 的 `-d` 也必须受 scope 约束
// ============================================================================
// 与本文件 paired 的那份 `api.directScope.test.js` 修的是 REST 侧；这一份修的是**第二条入口**。
// 起因（2026-09-25）：`bin/cli.js` 的 runSingleScan 里写着
//     const scopeRules = args.scope && !args.direct ? parseScope(...) : null;
// 注释还称"直连模式（-d）无 HTTP 请求可言，不参与 scope 判定"，而**同一句注释的上半段**
// 自称"与 scanRoutes sanitizeStart 同步拦截同构" —— REST 侧从 09-25 起已经按 DB 主机判
// scope 了，那句"同构"于是变成假话，真实效果是：
//     同一个 `-d mysql://root@10.0.0.9/db`，从 REST 进被拒，从 CLI 进一视同仁地放行。
// 修法是两条入口共用 `core/scopeGuard.assertDirectDbInScope`（判据只有一份）。
//
// 为什么从 `parseArgs` 起、经 runSingleScan 驱动（而不是直接单测那个 helper）：
//   helper 单测全绿也挡不住"入口没调它"—— 本仓在"只测被调函数→入口坏"上反复付过学费。
//   这里用的是 CLI 真实的 argv 形态，断言的是"越界时 sm.start 根本没被调用"（一个包都不发）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, runSingleScan } from '../bin/cli.js';
import { ErrorCode } from '../src/core/errors.js';

const SQL = 'SELECT * FROM users WHERE id={INJECT}';

// 假 ScanManager：记录 start 是否被调用（红线要求"越界时一个包都不发"）
function fakeManager() {
  const calls = [];
  return {
    calls,
    async start(input) {
      calls.push(input);
      return 'scan-stub';
    },
    scans: new Map([['scan-stub', { status: 'completed' }]]),
    getReport() {
      return { scanId: 'scan-stub', riskLevel: 'Low', points: [], vulns: [], summary: {} };
    },
  };
}

// 走 CLI 真实 argv：-d <dsn> --driver mysql --scope <cidr> --sql-template <tpl>
function cliArgs(dsn, extra = []) {
  return parseArgs(['-d', dsn, '--sql-template', SQL, '--driver', 'mysql', '--scope', '10.20.0.0/16', ...extra]);
}

test('CLI 直连：主机越界必须拒，且 sm.start 一次都没被调用（一个包都不发）', async () => {
  const sm = fakeManager();
  const args = cliArgs('mysql://root:pw@10.0.0.9:3306/targetdb');
  await assert.rejects(
    () => runSingleScan(sm, args.direct, args),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION && /授权范围|scope/i.test(e.message)
  );
  assert.equal(sm.calls.length, 0, '越界直连不得进入扫描启动');
});

test('CLI 直连：主机在范围内则放行（不因加了红线而错杀）', async () => {
  const sm = fakeManager();
  const args = cliArgs('mysql://root:pw@10.20.1.5:3306/targetdb');
  const report = await runSingleScan(sm, args.direct, args);
  assert.equal(sm.calls.length, 1, '圈内直连应照常启动');
  assert.equal(report.scanId, 'scan-stub');
  assert.equal(sm.calls[0].mode, 'direct');
});

test('CLI 直连：未配 --scope 时行为与历史一致（任意主机照常放行）', async () => {
  const sm = fakeManager();
  const args = parseArgs(['-d', 'mysql://root:pw@10.0.0.9:3306/db', '--sql-template', SQL, '--driver', 'mysql']);
  await runSingleScan(sm, args.direct, args);
  assert.equal(sm.calls.length, 1, '没配 scope 就不该新增拦截（红线是 opt-in 的硬约束）');
});

test('CLI 直连：内嵌驱动（不出网）配了 scope 也不得被误杀', async () => {
  const sm = fakeManager();
  const args = parseArgs([
    '-d', 'file::memory:?cache=shared', '--sql-template', SQL, '--driver', 'sqlite',
    '--scope', '10.20.0.0/16',
  ]);
  await runSingleScan(sm, args.direct, args);
  assert.equal(sm.calls.length, 1, '内嵌/内存库没有"主机"可言，不该被 scope 拒');
});

test('CLI 直连：声明了网络驱动却解析不出主机 ⇒ fail closed（未知即拒，不是"默认放过"）', async () => {
  const sm = fakeManager();
  // 畸形 DSN：既没有 //host 形态，driverType 又是 mysql（要出网的）
  const args = parseArgs([
    '-d', 'Driver={ODBC Driver 18};Server=;', '--sql-template', SQL, '--driver', 'mysql',
    '--scope', '10.20.0.0/16',
  ]);
  await assert.rejects(
    () => runSingleScan(sm, args.direct, args),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION && /无法确定数据库主机/.test(e.message)
  );
  assert.equal(sm.calls.length, 0);
});

test('CLI 的 HTTP 目标仍走 URL 判定（改动没把另一条路径带坏）', async () => {
  const sm = fakeManager();
  const args = parseArgs(['-u', 'http://10.0.0.9/item?id=1', '--scope', '10.20.0.0/16']);
  await assert.rejects(() => runSingleScan(sm, args.url, args), (e) => e.code === ErrorCode.SCOPE_VIOLATION);
  assert.equal(sm.calls.length, 0);
});

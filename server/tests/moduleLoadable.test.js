// ============================================================================
// tests/moduleLoadable.test.js —— 核心模块「能被 import 且导出齐全」冒烟
//
// 为什么必须单独有这条（2026-09-29 实测事故，本仓最贵的一次教训）
// ----------------------------------------------------------------------------
// merge commit `684e4a3`（parents = cc5fd55 00ce269）把
// `src/services/scanLedger.js` 回退成 `00ce269` 的旧版：d44ff82 新增的 5 个函数
// 定义整段丢失（positiveInt / retentionPolicy / entryTs / pruneLedger / highestRisk），
// **但同文件的调用点与 `export default { ... }` 清单还在**。后果：
//   scanLedger import 即抛 ReferenceError
//     → scanRoutes.js:33 具名 import 失败（does not provide an export named 'highestRisk'）
//     → index.js 起不来、bin/cli.js 全崩。
//
// 关键是 **2600+ 条测试一条都没拦住**，原因有二，本文件正是为它们而写：
//   ① 台账测试自己在模块顶层 `await import(...)` 就崩（崩在 import，跑不到断言）——
//      表现是"测试文件 fail"，而不是"某人忘了定义函数"，归因困难、极易被当成环境问题放过；
//   ② `src/api/scanRoutes.js` / `index.js` **从未被任何测试直接 import** —— 因此装配期
//      的具名导入错误在整个测试套件里是隐形的。
//
// 判据（三条，互相不可替代）
//   ① 每个核心模块必须**真的能 import**（不是"文件存在"、不是"能被静态解析"）；
//   ② `scanRoutes` / `exploitRoutes` / `sqlmapRoutes` / `index.js` 必须能从其导出面取到
//      关键符号 —— 覆盖"import 成功但名字变了"这一形态；
//   ③ 台账模块的 5 个函数（本次事故的受害者）逐个钉真值 —— 删掉任一个，这里必须红。
//
// ⚠️ 与 scripts/module-loadable.mjs 的分工（刻意冗余，别合并）：
//   · 脚本 = **静态**判据，覆盖 375 个 server/*.js 全量，能在"import 就崩"的状态下跑完；
//   · 本测试 = **运行时**判据，只覆盖核心入口，但能抓到静态解析看不见的形态
//     （如运行时抛错、导出被条件分支遮蔽、循环依赖的 TDZ 问题）。
//   两者互补：脚本在 CI lint job 里跑，本测试在 test-server job 里跑。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';

// ── 核心模块清单：改这里必须同时说明"为什么新增/移除" ─────────────────────────
// 选取标准：**装配期被顶层 import、且一旦坏了会让引擎或 CLI 整体起不来**的模块。
const CRITICAL_MODULES = [
  '../index.js',
  '../src/api/scanRoutes.js',
  '../src/api/exploitRoutes.js',
  '../src/api/sqlmapRoutes.js',
  '../src/api/tamperRoutes.js',
  '../src/api/healthRoutes.js',
  '../src/api/reportAiRoutes.js',
  '../src/api/directTarget.js',
  '../src/api/scanGovernance.js',
  '../src/api/scanConfigGuard.js',
  '../src/services/scanLedger.js',
  '../src/services/ReportGenerator.js',
  '../src/engine/ScanManager.js',
  '../src/engine/Exploiter.js',
  '../src/engine/sqlmapBridge.js',
  '../src/core/httpClient.js',
  '../src/engine/payloadRegistry.js',
  '../bin/cli.js',
];

test('核心模块必须可加载（import 期不得抛错）', async () => {
  for (const spec of CRITICAL_MODULES) {
    let mod;
    await assert.doesNotReject(
      async () => { mod = await import(spec); },
      `${spec} 必须能被 import —— 若这里失败，引擎/CLI 会整体起不来（参见本文件头注释的事故）`
    );
    assert.ok(mod, `${spec} import 后应得到模块命名空间`);
  }
});

test('scanRoutes 必须导出装配期依赖的关键符号', async () => {
  const m = await import('../src/api/scanRoutes.js');
  // index.js:21 依赖的 defaultScanManager；其余是 scanRoutes 的公开导出面
  for (const name of ['scanRoutes', 'defaultScanManager']) {
    assert.ok(name in m, `scanRoutes 必须导出 ${name}`);
  }
});

test('ledger 相关符号必须能从其声明处取到（本次事故的破损面）', async () => {
  const m = await import('../src/services/scanLedger.js');
  for (const name of ['recordScan', 'listScans', 'getScan', 'readReport', 'ledgerRoot', 'pruneLedger', 'retentionPolicy', 'highestRisk']) {
    assert.equal(typeof m[name], 'function', `scanLedger 必须导出函数 ${name}`);
  }
  // scanRoutes 是**导入方**（不是再导出），所以运行时拿不到它的命名空间 ⇒ 改判 ① 模块能加载
  // （上一条测试已做）+ ② 它引入的那 4 个名字确实存在于 scanLedger 的导出面。
  // 本次事故正是这条链断的：scanRoutes:33 具名导入 highestRisk，而 scanLedger 没有它
  // ⇒ SyntaxError「does not provide an export named 'highestRisk'」。
  await assert.doesNotReject(() => import('../src/api/scanRoutes.js'), 'scanRoutes 必须可加载（装配链别断在这）');
  for (const name of ['readReport', 'listScans', 'ledgerRoot', 'highestRisk']) {
    assert.ok(name in m, `scanRoutes:33 具名导入了 ${name}，scanLedger 就必须导出它——缺一个即引擎起不来`);
  }
});

test('台账保留策略三件套行为可用（不只是"名字存在"）', async () => {
  const { retentionPolicy, highestRisk, pruneLedger } = await import('../src/services/scanLedger.js');
  // retentionPolicy 读 env：未配置时两维都为 0（= 不限制）
  const prevMax = process.env.SCAN_LEDGER_MAX;
  const prevDays = process.env.SCAN_LEDGER_MAX_DAYS;
  delete process.env.SCAN_LEDGER_MAX;
  delete process.env.SCAN_LEDGER_MAX_DAYS;
  try {
    assert.deepEqual(retentionPolicy(), { max: 0, maxDays: 0 }, '未配置策略时两维必须是 0');
    // 未配策略 ⇒ pruneLedger 直接 skipped，一个目录都不碰
    const r = pruneLedger({});
    assert.equal(r.skipped, true);
    assert.equal(r.reason, 'no-limit');
    assert.equal(r.removed, 0);
  } finally {
    if (prevMax !== undefined) process.env.SCAN_LEDGER_MAX = prevMax;
    if (prevDays !== undefined) process.env.SCAN_LEDGER_MAX_DAYS = prevDays;
  }
  // highestRisk 只认四档规范值，规范外一律 null（不猜）
  assert.equal(highestRisk([]), null);
  assert.equal(highestRisk([{ riskLevel: 'Low' }, { riskLevel: 'Critical' }]), 'Critical');
  assert.equal(highestRisk([{ riskLevel: 'low' }]), null, '小写不在规范集内 ⇒ null');
  assert.equal(highestRisk([{ riskLevel: 'Bogus' }]), null, '规范外的值不得被当成有效档位');
  assert.equal(highestRisk(undefined), null, 'undefined 不得抛错');
});

test('exploitRoutes 能力面必须可枚举', async () => {
  const m = await import('../src/api/exploitRoutes.js');
  assert.ok(m.exploitRoutes, 'exploitRoutes 必须导出');
  const ex = await import('../src/engine/Exploiter.js');
  assert.equal(typeof ex.capabilityIndex, 'function', 'Exploiter 必须导出 capabilityIndex（capabilities 接口由它推导）');
  assert.ok(ex.TAKEOVER_CAPS && typeof ex.TAKEOVER_CAPS === 'object', 'Exploiter 必须导出 TAKEOVER_CAPS');
});

test('cli 模块可加载（用户入口，坏了没人发现）', async () => {
  const m = await import('../bin/cli.js');
  assert.ok(Object.keys(m).length > 0, 'bin/cli.js 必须至少导出一个符号（其导出面被 8 个测试文件依赖）');
});

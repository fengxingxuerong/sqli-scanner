#!/usr/bin/env node
// ============================================================================
// pack-install-check.mjs —— npm 包「registry 式安装」端到端验证（D184，收编 D182 遗留）
//
// 为什么有它：pack-check.mjs 用软链复用本仓 node_modules，证明的是「包内容完整」；
// 而「拿到干净机器上 npm install <tgz> 之后能不能装、能不能跑」一直是 TODO 里挂着的
// 遗留项（D175/D182 两次都没跑）。本脚本把这件事钉成一条命令：
//   ① npm pack 出真包（files 白名单产物）；
//   ② 干净临时目录 `npm install <tgz>`——真实走 registry/npm cache 解析依赖（express/axios 等）；
//   ③ 断言安装树：包目录只含 bin/ src/ index.js package.json，不含 tests/ ledger/；
//   ④ 实跑：--help 含 mcp + 内存直连扫描 exit=2 且 report.json vulns ≥ 1。
// 注意：需要网络（或 warm 的 npm cache）解析依赖，因此**不进 gate:close**；
// 定位是发版前的一次性体检（docs/release-process.md 引用），与 pack-check（门禁）互补。
//
// 用法：
//   node scripts/pack-install-check.mjs            # 全流程真跑
//   node scripts/pack-install-check.mjs --selftest # 自证安装树判据不空转（纯函数部分）
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// 跑命令的公共件（run）与 selftest 跑法（selftestCases）抽到 lib，与 pack-check 同源（D184）
import { run, selftestCases } from './lib/packCheckCommon.mjs';
const ROOT = path.resolve(HERE, '..');
const SERVER = path.join(ROOT, 'server');

/** 安装树断言：包目录允许的条目与禁止的目录。 * @returns {string[]} 违规说明（空数组 = 通过） */
function assertInstalledTree(pkgDir, entries) {
  const errors = [];
  const rel = entries.map((e) => e.replaceAll('\\', '/'));
  const allow = ['bin/', 'src/', 'index.js', 'package.json'];
  const top = new Set(rel.map((e) => e.split('/')[0]).filter(Boolean));
  for (const t of top) {
    if (!allow.some((a) => (a.endsWith('/') ? t === a.slice(0, -1) : t === a))) {
      errors.push(`包目录出现白名单外顶层条目：${t}（files 白名单是 bin/ src/ index.js）`);
    }
  }
  for (const banned of ['tests', 'ledger']) {
    if (rel.some((e) => e === banned || e.startsWith(`${banned}/`))) {
      errors.push(`安装树里不该有 ${banned}/（27 MB 时代的遗留物又回来了？）`);
    }
  }
  for (const must of ['bin/cli.js', 'package.json', 'index.js']) {
    if (!rel.includes(must)) errors.push(`缺必备文件：${must}`);
  }
  return errors;
}

/** ① 打包（与 pack-check 同一产物：files 白名单决定内容） @returns {{tgz:string, sizeMB:number}} */
function packPhase(tmp) {
  const tgzName = run('npm', ['pack', '--pack-destination', tmp, '--silent'], { cwd: SERVER }).trim().split(/\r?\n/).pop();
  const tgz = path.join(tmp, tgzName);
  const sizeMB = fs.statSync(tgz).size / 1024 / 1024;
  console.log(`[pack-install] ✓ npm pack：${tgzName}（${sizeMB.toFixed(2)} MB）`);
  return { tgz, sizeMB };
}

/** ② 干净目录真实安装（registry / npm cache 解析 14 个直接依赖） @returns {string} 包目录 */
function installPhase(tmp, tgz) {
  const appDir = path.join(tmp, 'app');
  fs.mkdirSync(appDir, { recursive: true });
  const t0 = Date.now();
  run('npm', ['install', tgz, '--no-audit', '--no-fund', '--loglevel=error'], { cwd: appDir });
  console.log(`[pack-install] ✓ npm install：${((Date.now() - t0) / 1000).toFixed(1)}s（依赖走 registry/cache 真实解析）`);
  return path.join(appDir, 'node_modules', pkgName());
}

/** ③ 安装树断言（白名单顶层 + 无 tests/ledger + 必备文件） */
function treePhase(pkgDir) {
  const walk = (dir, base = '') => fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const rel = base ? `${base}/${d.name}` : d.name;
    return d.isDirectory() ? walk(path.join(dir, d.name), rel) : [rel];
  });
  const entries = walk(pkgDir);
  const errs = assertInstalledTree(pkgDir, entries);
  if (errs.length) {
    console.error('[pack-install] ✗ 安装树断言未通过：');
    for (const e of errs.slice(0, 12)) console.error('  · ' + e);
    process.exitCode = 1;
    return false;
  }
  const deps = fs.readdirSync(path.dirname(pkgDir)).filter((n) => !n.startsWith('.'));
  console.log(`[pack-install] ✓ 安装树干净：包目录 ${entries.length} 个文件、顶层依赖 ${deps.length} 个、无 tests/ledger`);
  return true;
}

/** ④ 实跑：--help + 内存直连扫描（期望 exit=2 且命中 ≥1） */
function smokePhase(pkgDir, tmp) {
  const cli = path.join(pkgDir, 'bin', 'cli.js');
  const help = run(process.execPath, [cli, '--help']);
  if (!/mcp/.test(help)) throw new Error('--help 输出里没有 mcp 子命令');
  const outDir = path.join(tmp, 'out');
  let scanExit = 0;
  try {
    run(process.execPath, [cli, '-d', 'memory://x', '--driver', 'memory',
      '--sql-template', 'SELECT * FROM users WHERE id={INJECT}', '-o', outDir + '/']);
  } catch (e) {
    scanExit = Number((e.message.match(/exit=(\d+)/) || [])[1] || 1);
    if (scanExit !== 2) throw e;
  }
  const report = JSON.parse(fs.readFileSync(path.join(outDir, 'report.json'), 'utf8'));
  if (!Array.isArray(report.vulns) || report.vulns.length < 1) {
    throw new Error(`安装产物扫描没出命中（vulns=${report.vulns?.length}）`);
  }
  console.log(`[pack-install] ✓ 安装后可跑：--help 正常、内存扫描 exit=${scanExit}、命中 ${report.vulns.length} 条`);
}

/** 从 server/package.json 读包名（唯一真源） */
function pkgName() {
  return JSON.parse(fs.readFileSync(path.join(SERVER, 'package.json'), 'utf8')).name;
}

function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pack-install-'));
  try {
    const { tgz } = packPhase(tmp);
    const pkgDir = installPhase(tmp, tgz);
    if (!treePhase(pkgDir)) return;
    smokePhase(pkgDir, tmp);
  } catch (e) {
    console.error('[pack-install] ✗ ' + String(e?.message || e).slice(0, 600));
    process.exitCode = 1;
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* 临时目录漏清不影响结论 */ }
  }
}

// ── 自证：安装树判据必须能红 ──────────────────────────────────────────────────
function selftest() {
  const good = ['package.json', 'index.js', 'bin/cli.js', 'src/engine/payloads/registry.json', 'src/mcp/tools.js'];
  const cases = [
    { name: '带 tests/', sample: [...good, 'tests/x.test.js'], expect: /tests/ },
    { name: '带 ledger/', sample: [...good, 'ledger/x.json'], expect: /ledger/ },
    { name: '白名单外顶层目录', sample: [...good, 'dist-engine/x.js'], expect: /白名单外/ },
    { name: '缺 bin/cli.js', sample: good.filter((e) => e !== 'bin/cli.js'), expect: /缺必备文件/ },
    { name: '缺 package.json', sample: good.filter((e) => e !== 'package.json'), expect: /缺必备文件/ },
  ];
  selftestCases((entries) => assertInstalledTree('pkg', entries), good, cases, 'pack-install', '合格安装树');
}

if (process.argv.includes('--selftest')) selftest();
else main();

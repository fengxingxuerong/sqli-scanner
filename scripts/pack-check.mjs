#!/usr/bin/env node
// ============================================================================
// pack-check.mjs —— npm 包内容体检（D182）
//
// 为什么有它：`npm pack` 之前打出 **27 MB**（把 `tests/` 与运行期 `ledger/` 一起装进去了），
// 而「发出去的包能不能跑」从没被验证过——本仓反复栽在「本机好好的，拿出去少个文件」。
// 这里把两件事钉成一条命令：
//   ① **瘦**：体积上限 + 必须不含 tests/ledger/node_modules；
//   ② **全**：引擎运行期真的读到的资产（registry.json / tamper / mcp）必须在包里，
//      并且**解包后真能跑**（--help + 一次离线直连扫描出 3 条命中）。
// 注意：依赖（axios/express/…）由安装方的 node_modules 提供，本脚本用软链复用本仓依赖，
// 因此它证明的是「包内容完整」，不是「registry 上装得下来」——后者见 CHANGELOG 记录。
//
// 用法：
//   node scripts/pack-check.mjs            # 打包 + 断言 + 解包实跑
//   node scripts/pack-check.mjs --selftest # 自证判据不空转（纯函数部分）
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// 跑命令的公共件（run）与 selftest 跑法（selftestCases）抽到 lib，与 pack-install-check 同源（D184）
import { run, selftestCases } from './lib/packCheckCommon.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const SERVER = path.join(ROOT, 'server');

/** 体积上限（MB）：1.2 MB 实测，留 4 倍余量给未来新增资产；再大就该查是不是又打进了数据。 */
const MAX_MB = 5;

/** 必须出现在包里的运行期资产（少一个 = 引擎在别人机器上跑不起来） */
const REQUIRED_ENTRIES = [
  'package/package.json',
  'package/bin/cli.js',
  'package/index.js',
  'package/src/engine/payloads/registry.json',
  'package/src/mcp/tools.js',
  'package/src/core/tamper/index.js',
];

/** 绝不允许进包的目录（测试 / 运行期数据 / 依赖） */
const FORBIDDEN_PREFIXES = ['package/tests/', 'package/ledger/', 'package/node_modules/', 'package/coverage/'];

/**
 * 断言包体：体积、必备条目、禁止条目。
 * @param {{sizeBytes:number, entries:string[]}} pack 包体信息（`entries` 为 tar 内相对路径）
 * @returns {string[]} 违规说明（空数组 = 通过）
 */
function assertPack(pack) {
  const errors = [];
  const mb = pack.sizeBytes / (1024 * 1024);
  if (!(mb > 0)) errors.push('包体积为 0：npm pack 可能失败');
  if (mb > MAX_MB) errors.push(`包体积 ${mb.toFixed(1)} MB > 上限 ${MAX_MB} MB（多半又打进了 tests/ledger）`);
  for (const need of REQUIRED_ENTRIES) {
    if (!pack.entries.includes(need)) errors.push(`缺运行期资产：${need}`);
  }
  for (const e of pack.entries) {
    const bad = FORBIDDEN_PREFIXES.find((p) => e.startsWith(p));
    if (bad) errors.push(`不该进包的条目：${e}（命中禁止前缀 ${bad}）`);
  }
  return errors;
}

/**
 * 解析可用的 tar 可执行文件：Windows 钉 System32 自带 bsdtar（防 GNU tar 的 rmt 误判），
 * 不存在（老系统/精简镜像）时回落 'tar' 交由 PATH。非 Windows 一律 'tar'。
 * @returns {string} tar 可执行文件路径或命令名
 */
function winTar() {
  if (process.platform !== 'win32') return 'tar';
  const sysTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
  return fs.existsSync(sysTar) ? sysTar : 'tar';
}

function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pack-check-'));
  try {
    const tgzName = run('npm', ['pack', '--pack-destination', tmp, '--silent'], { cwd: SERVER }).trim().split(/\r?\n/).pop();
    const tgz = path.join(tmp, tgzName);
    const sizeBytes = fs.statSync(tgz).size;
    // [D189] tar 不许依赖 PATH 解析：Git Bash 环境下 GNU tar 会把 `C:\...` 当 rmt 远程主机
    // （"Cannot connect to C: resolve failed"），门禁红绿随 PATH 漂移。Windows 优先钉
    // System32 自带 bsdtar（原生支持盘符路径），其余平台保持 'tar'。
    const entries = run(winTar(), ['-tzf', tgz]).split(/\r?\n/).filter(Boolean);
    const errors = assertPack({ sizeBytes, entries });
    if (errors.length) {
      console.error('[pack-check] ✗ 包体体检未通过：');
      for (const e of errors.slice(0, 12)) console.error('  · ' + e);
      process.exitCode = 1;
      return;
    }
    console.log(`[pack-check] ✓ 包体 ${(sizeBytes / 1024 / 1024).toFixed(2)} MB、${entries.length} 个条目、必备资产齐全、无 tests/ledger`);

    // ② 解包后真跑：--help + 一次内存直连扫描（不联网、不需外部数据库）
    const appDir = path.join(tmp, 'app');
    fs.mkdirSync(appDir, { recursive: true });
    run(winTar(), ['-xzf', tgz, '-C', appDir]);
    const pkgDir = path.join(appDir, 'package');
    // 依赖复用本仓 server/node_modules（证明的是「包内容完整」，不是「registry 装得下来」）
    fs.symlinkSync(path.join(SERVER, 'node_modules'), path.join(pkgDir, 'node_modules'), 'junction');
    const help = run(process.execPath, [path.join(pkgDir, 'bin', 'cli.js'), '--help']);
    if (!/mcp/.test(help)) throw new Error('--help 输出里没有 mcp 子命令：包内 CLI 可能不完整');
    const outDir = path.join(tmp, 'out');
    let scanExit = 0;
    try {
      run(process.execPath, [
        path.join(pkgDir, 'bin', 'cli.js'),
        '-d', 'memory://x', '--driver', 'memory',
        '--sql-template', 'SELECT * FROM users WHERE id={INJECT}',
        '-o', outDir + '/',
      ]);
    } catch (e) {
      // 期望 exit=2（发现 High）——这本身就是「引擎在解包产物里跑通了」的证据
      scanExit = Number((e.message.match(/exit=(\d+)/) || [])[1] || 1);
      if (scanExit !== 2) throw e;
    }
    const reportPath = path.join(outDir, 'report.json');
    const report = JSON.parse(run(process.execPath, ['-e', `process.stdout.write(require('fs').readFileSync(${JSON.stringify(reportPath)},'utf8'))`]));
    if (!Array.isArray(report.vulns) || report.vulns.length < 1) {
      throw new Error(`解包产物扫描没出命中（vulns=${report.vulns?.length}）——包内 payload 资产可能缺失`);
    }
    console.log(`[pack-check] ✓ 解包后可跑：--help 正常、直连扫描 exit=${scanExit}、命中 ${report.vulns.length} 条`);
  } catch (e) {
    console.error('[pack-check] ✗ ' + String(e?.message || e).slice(0, 600));
    process.exitCode = 1;
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* 临时目录漏清不影响结论 */ }
  }
}

// ── 自证：包体判据必须能红 ────────────────────────────────────────────────────
function selftest() {
  const good = { sizeBytes: 1.2 * 1024 * 1024, entries: [...REQUIRED_ENTRIES, 'package/src/engine/audit.js'] };
  const cases = [
    { name: '超体积上限', sample: { ...good, sizeBytes: (MAX_MB + 1) * 1024 * 1024 }, expect: /上限/ },
    { name: '带 tests/', sample: { ...good, entries: [...REQUIRED_ENTRIES, 'package/tests/audit.test.js'] }, expect: /不该进包/ },
    { name: '带 ledger 运行期数据', sample: { ...good, entries: [...REQUIRED_ENTRIES, 'package/ledger/x.json'] }, expect: /不该进包/ },
    { name: '缺 registry.json', sample: { ...good, entries: REQUIRED_ENTRIES.filter((e) => !e.includes('registry')) }, expect: /缺运行期资产/ },
    { name: '缺 mcp', sample: { ...good, entries: REQUIRED_ENTRIES.filter((e) => !e.includes('mcp')) }, expect: /缺运行期资产/ },
    { name: '空包', sample: { sizeBytes: 0, entries: [] }, expect: /体积为 0|缺运行期资产/ },
  ];
  selftestCases(assertPack, good, cases, 'pack-check', '合格包体');
}

if (process.argv.includes('--selftest')) selftest();
else main();

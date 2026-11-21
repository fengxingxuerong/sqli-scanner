#!/usr/bin/env node
// ============================================================================
// scripts/portable-smoke.mjs —— [D142 2026-10-23] 免安装便携包「干净解压」冒烟
//
// 为什么不能在原地跑：D139 就吃过这个形态的亏 —— 在仓库里跑 exe 时它能向上找到
// package.json，于是版本自报 1.2.0；**复制到仓库外**才暴露 `0.0.0+unknown`。
// 便携包的价值就在于「换一台没装仓库的机器也能跑」，所以断言必须在**干净解压目录**里做。
//
// 断言（任一不满足即 exit 1，不假装通过）：
//   ① 解压后能启动壳，且壳**自己拉起 sidecar**（引擎端口开始监听）；
//   ② `/api/health` 自报版本 === package.json 版本（防 D128 那类「装到用户机器上版本是错的」）；
//   ③ `authEnabled === true`（壳注入一次性 token 的真实链路证据）；
//   ④ 退出后清理：不留进程、不留临时目录。
//
// 判定函数与命名约定见 scripts/lib/portable.mjs（与 build-portable 共用同一来源）。
//
// 用法：
//   node scripts/portable-smoke.mjs                     # 取 dist-portable/ 下最新的 zip
//   node scripts/portable-smoke.mjs --zip <path.zip>
//   node scripts/portable-smoke.mjs --dir <portable-dir>   # 已解压目录（跳过解压）
//   node scripts/portable-smoke.mjs --selftest             # 自证判定函数（不碰产物）
// 非 Windows 平台：输出 `[SKIP]` 并 exit 0（便携包目前只产 Windows 产物；SKIP 不计通过）。
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { failWith, fetchHealthData, isDirectRun, judgeHealth, portableLayout, readOpt, runSelftest, skipWith, smokeChecks } from './lib/portable.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TAG = '[portable-smoke]';
const fail = (msg) => failWith(TAG, msg);
const skip = (msg) => skipWith(TAG, msg);

/**
 * 自证：判定函数必须对每条失败路径有反应（用例在 scripts/lib/portable.mjs）。
 * @returns {void} 失败时直接 exit 1
 */
function selftest() {
  runSelftest(TAG, smokeChecks(), '版本/鉴权/状态/缺失响应 四条失败路径');
}

/** 找监听端口（壳给 sidecar 选的端口是随机的） */
function listenPortsOf(pid) {
  const r = spawnSync('powershell', [
    '-NoProfile',
    '-Command',
    `(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq ${pid} } | Select-Object -First 1).LocalPort`,
  ], { encoding: 'utf8' });
  const port = Number(String(r.stdout || '').trim());
  return Number.isFinite(port) && port > 0 ? port : null;
}

/** 取最近启动的同类进程（冒烟结束会清理所有 sqli-* 进程，避免误杀无关实例） */
function newestPidOf(name) {
  const r = spawnSync('powershell', [
    '-NoProfile',
    '-Command',
    `(Get-Process -Name ${name} -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1).Id`,
  ], { encoding: 'utf8' });
  const pid = Number(String(r.stdout || '').trim());
  return Number.isFinite(pid) && pid > 0 ? pid : null;
}

/** 探 /api/health（实现与 sidecar 冒烟共用 scripts/lib/portable.mjs，避免两份实现漂移） */
const fetchHealth = fetchHealthData;

/** 目录非空判定：不采信命令自报的 exit 0（Expand-Archive 曾静默产出空目录） */
function nonEmptyDir(d) {
  try { return fs.existsSync(d) && fs.readdirSync(d).length > 0; } catch { return false; }
}

/**
 * 解压 zip 到目标目录。
 * 不用 Expand-Archive：2026-11-21 两个 tag 场实证 runner 的 PowerShell 7
 * Microsoft.PowerShell.Archive 模块在 ExtractToDirectory 上报
 * `MethodCountCouldNotFindBest`，且 Expand-Archive 未返回非 0 ⇒ 静默空目录，
 * 冒烟把「解压没成功」误判成「壳/边车缺失」。
 * 主路用 .NET ZipFile（PS 5.1 / 7 都有），回退系统 tar（Win10 自带 bsdtar）；
 * 两条路都以「目标目录非空」为成功，最终关键文件由 main() 再核一遍。
 * @param {string} zip zip 路径
 * @param {string} dest 解压目标（不存在时由解压器创建）
 * @returns {void} 两条路都失败时 exit 1
 */
function extractZip(zip, dest) {
  const q = (p) => `'${String(p).replace(/'/g, "''")}'`;
  fs.rmSync(dest, { recursive: true, force: true });

  const psCmd =
    'Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue; ' +
    `[System.IO.Compression.ZipFile]::ExtractToDirectory(${q(zip)}, ${q(dest)})`;
  const r = spawnSync('powershell', ['-NoProfile', '-Command', psCmd], { stdio: 'inherit' });
  if (r.status === 0 && nonEmptyDir(dest)) return;

  console.log(`${TAG} .NET 解压不可用（exit=${r.status}），回退 tar -xf`);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  // 显式指向系统 bsdtar：Git Bash 的 PATH 里 msys tar 会把 D:\... 误当 host:path
  const sysTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
  const tarBin = fs.existsSync(sysTar) ? sysTar : 'tar';
  const t = spawnSync(tarBin, ['-xf', zip, '-C', dest], { stdio: 'inherit' });
  if (t.status === 0 && nonEmptyDir(dest)) return;

  fail(`解压失败：${zip}（.NET exit=${r.status}, tar exit=${t.status}，目标目录仍为空或不存在）`);
}

/** 解析输入：--dir 直用；否则找 zip 解压到临时目录 */
function resolveWorkDir(argv) {
  const givenDir = readOpt(argv, '--dir');
  if (givenDir) return { workDir: givenDir, tempRoot: null };

  const givenZip = readOpt(argv, '--zip');
  const zip = givenZip
    ? path.resolve(givenZip)
    : (() => {
        const base = path.join(ROOT, 'dist-portable');
        if (!fs.existsSync(base)) return null;
        const zips = fs
          .readdirSync(base)
          .filter((f) => f.endsWith('.zip'))
          .map((f) => path.join(base, f))
          .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
        return zips[0] ?? null;
      })();
  if (!zip || !fs.existsSync(zip)) {
    skip('没有可冒烟的 zip（先跑 node scripts/build-portable.mjs，或用 --zip/--dir 指定）');
  }
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sqli-portable-smoke-'));
  const workDir = path.join(tempRoot, 'extracted');
  extractZip(zip, workDir);
  console.log(`${TAG} 干净解压：${workDir}`);
  return { workDir, tempRoot };
}

/** 起壳并等 sidecar 监听；返回 { appPid, enginePid, port }（超时即 fail，不返回半成品） */
async function launchAndWait(workDir, layout) {
  const app = spawn(path.join(workDir, layout.shell), [], { cwd: workDir, stdio: 'ignore' });
  const appPid = app.pid;
  console.log(`${TAG} 启动壳：pid=${appPid}（cwd=${workDir}）`);
  let enginePid = null;
  let port = null;
  const deadline = Date.now() + 40000;
  while (Date.now() < deadline && (!enginePid || !port)) {
    await new Promise((r) => setTimeout(r, 1000));
    if (!enginePid) enginePid = newestPidOf(path.basename(layout.sidecarDst, '.exe'));
    if (enginePid) port = listenPortsOf(enginePid);
  }
  if (!enginePid) {
    try { process.kill(appPid); } catch { /* 已退出 */ }
    fail('壳起来了但**没有拉起 sidecar**（sqli-engine 进程未出现）—— 便携包里 sidecar 缺失或名字不对');
  }
  if (!port) {
    try { process.kill(appPid); process.kill(enginePid); } catch { /* 已退出 */ }
    fail(`sidecar（pid=${enginePid}）没有监听端口 —— 看壳的日志（引擎崩溃时这里会空）`);
  }
  console.log(`${TAG} sidecar 已拉起：pid=${enginePid}，监听 127.0.0.1:${port}`);
  return { appPid, enginePid, port };
}

/** 清理：杀进程 + 删临时目录（幂等；清理失败不影响判定结论） */
function cleanup(ids, tempRoot) {
  for (const pid of ids) {
    try { process.kill(pid); } catch { /* 已退出 */ }
  }
  spawnSync('powershell', ['-NoProfile', '-Command', 'Get-Process -Name sqli-engine,sqli-scanner -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue'], { stdio: 'ignore' });
  if (tempRoot) fs.rmSync(tempRoot, { recursive: true, force: true });
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
async function main() {
  const argv = process.argv.slice(2);
  if (process.platform !== 'win32') skip(`便携包目前只产 Windows 产物（当前平台 ${process.platform}）`);
  const layout = portableLayout(process.platform, process.arch);

  const { workDir, tempRoot } = resolveWorkDir(argv);
  for (const need of [layout.shell, layout.sidecarDst]) {
    if (!fs.existsSync(path.join(workDir, need))) {
      fail(
        `解压目录里没有 ${need}：${workDir}\n` +
          '  [Tauri 命名约定] sidecar 必须改名成 sqli-engine[.exe] —— 壳用 shell().sidecar("sqli-engine") 找它。'
      );
    }
  }

  const { appPid, enginePid, port } = await launchAndWait(workDir, layout);
  const health = await fetchHealth(port);
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  const problems = judgeHealth(health, version);
  cleanup([enginePid, appPid], tempRoot);

  if (problems.length) {
    console.error(`${TAG} ✗ 冒烟失败：`);
    for (const p of problems) console.error(`    · ${p}`);
    process.exit(1);
  }
  console.log(
    `${TAG} ✓ 冒烟通过：壳拉起 sidecar · /api/health version=${health.version}（source=${health.versionSource}）· authEnabled=true · 已清理`
  );
}

if (process.argv.includes('--selftest')) {
  selftest();
  process.exit(0);
}

if (isDirectRun(import.meta.url)) await main();
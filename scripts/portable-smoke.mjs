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
// 用法：
//   node scripts/portable-smoke.mjs                     # 取 dist-portable/ 下最新的 zip
//   node scripts/portable-smoke.mjs --zip <path.zip>
//   node scripts/portable-smoke.mjs --dir <portable-dir>   # 已解压目录（跳过解压）
// 非 Windows 平台：输出 `[SKIP]` 并 exit 0（便携包目前只产 Windows 产物；SKIP 不计通过）。
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : null;
};
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

function skip(msg) {
  console.log(`[portable-smoke] [SKIP] ${msg}`);
  process.exit(0);
}
function fail(msg) {
  console.error(`[portable-smoke] ✗ ${msg}`);
  process.exit(1);
}

if (process.platform !== 'win32') skip(`便携包目前只产 Windows 产物（当前平台 ${process.platform}）`);

// ── 取输入：zip 或已解压目录 ─────────────────────────────────────────────────
const givenDir = opt('--dir');
let workDir = givenDir;
let tempRoot = null;
if (!givenDir) {
  const givenZip = opt('--zip');
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
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sqli-portable-smoke-'));
  workDir = path.join(tempRoot, 'extracted');
  fs.mkdirSync(workDir, { recursive: true });
  const r = spawnSync('powershell', ['-NoProfile', '-Command', `Expand-Archive -Path '${zip}' -DestinationPath '${workDir}' -Force`], { stdio: 'inherit' });
  if (r.status !== 0) fail(`解压失败：${zip}`);
  console.log(`[portable-smoke] 干净解压：${workDir}`);
}

const shellExe = path.join(workDir, 'sqli-scanner.exe');
const sidecarExe = path.join(workDir, 'sqli-engine.exe');
if (!fs.existsSync(shellExe)) fail(`解压目录里没有 sqli-scanner.exe：${workDir}`);
if (!fs.existsSync(sidecarExe)) {
  fail(
    `解压目录里没有 sqli-engine.exe：${workDir}\n` +
      '  [Tauri 命名约定] sidecar 必须改名成 sqli-engine.exe —— 壳用 shell().sidecar("sqli-engine") 找它。'
  );
}

/** 探健康端点（壳给 sidecar 选的端口是随机的，所以先扫监听端口再打） */
function listenPortsOf(pid) {
  const r = spawnSync('powershell', [
    '-NoProfile',
    '-Command',
    `(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq ${pid} } | Select-Object -First 1).LocalPort`,
  ], { encoding: 'utf8' });
  const port = Number(String(r.stdout || '').trim());
  return Number.isFinite(port) && port > 0 ? port : null;
}
function childPidOf(name) {
  // 取最近启动的那个同类进程（冒烟前后会清理所有 sqli-* 进程，避免误杀无关实例）
  const r = spawnSync('powershell', [
    '-NoProfile',
    '-Command',
    `(Get-Process -Name ${name} -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1).Id`,
  ], { encoding: 'utf8' });
  const pid = Number(String(r.stdout || '').trim());
  return Number.isFinite(pid) && pid > 0 ? pid : null;
}
const getJson = (port, p) =>
  new Promise((resolve) => {
    const q = http.get({ host: '127.0.0.1', port, path: p, timeout: 3000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { resolve(null); }
      });
    });
    q.on('error', () => resolve(null));
    q.on('timeout', () => { q.destroy(); resolve(null); });
  });

// ── 起壳，等 sidecar 与健康端点 ──────────────────────────────────────────────
const app = spawn(shellExe, [], { cwd: workDir, detached: false, stdio: 'ignore' });
const startedAt = Date.now();
const appPid = app.pid;
console.log(`[portable-smoke] 启动壳：pid=${appPid}（cwd=${workDir}）`);

let enginePid = null;
let port = null;
const deadline = Date.now() + 40000;
while (Date.now() < deadline && (!port || !enginePid)) {
  await new Promise((r) => setTimeout(r, 1000));
  if (!enginePid) enginePid = childPidOf('sqli-engine', startedAt);
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
console.log(`[portable-smoke] sidecar 已拉起：pid=${enginePid}，监听 127.0.0.1:${port}`);

const health = (await getJson(port, '/api/health'))?.data ?? null;
const cleanup = () => {
  for (const pid of [enginePid, appPid]) {
    try { process.kill(pid); } catch { /* 已退出 */ }
  }
  spawnSync('powershell', ['-NoProfile', '-Command', "Get-Process -Name sqli-engine,sqli-scanner -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"], { stdio: 'ignore' });
  if (tempRoot) fs.rmSync(tempRoot, { recursive: true, force: true });
};

if (!health) {
  cleanup();
  fail('sidecar 在监听但 /api/health 取不到（引擎启动失败？）');
}

// ── 断言 ─────────────────────────────────────────────────────────────────────
const problems = [];
if (health.version !== VERSION) {
  problems.push(`版本自报不符：health.version=${health.version}，package.json=${VERSION}（便携包最怕这个：装到别的机器上报错版本）`);
}
if (health.authEnabled !== true) {
  problems.push(`authEnabled=${health.authEnabled}，期望 true —— 壳注入一次性 token 的链路没生效`);
}
if (health.status !== 'up') problems.push(`status=${health.status}，期望 up`);

cleanup();
if (problems.length) {
  console.error('[portable-smoke] ✗ 冒烟失败：');
  for (const p of problems) console.error(`    · ${p}`);
  process.exit(1);
}
console.log(
  `[portable-smoke] ✓ 冒烟通过：壳拉起 sidecar · /api/health version=${health.version}（source=${health.versionSource}）· authEnabled=true · 已清理`
);
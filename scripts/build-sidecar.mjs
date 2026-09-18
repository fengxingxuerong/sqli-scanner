#!/usr/bin/env node
// ============================================================================
// scripts/build-sidecar.mjs —— 把引擎打成 Tauri sidecar 单文件可执行（Node SEA）
//
// 为什么用 SEA 而不是 pkg：
//   本机实测 `@yao-pkg/pkg --target node20-win-x64` 没有预编译 base binary，
//   退化为**从源码编译 Node**，随后因缺 NASM 直接失败（日志：Looking for NASM → Error）。
//   Node 22 自带的 SEA 用本机 node.exe 作 base，无需下载/编译，几十秒出包。
//
// 产物：src-tauri/binaries/sqli-engine-<target-triple>[.exe]
//   Tauri 侧由 bundle.externalBin: ["binaries/sqli-engine"] 声明（缺这行 `tauri build`
//   不会把 exe 打进包，运行时 shell().sidecar("sqli-engine") 直接找不到）。
//
// 已知限制（务必知悉）：
//   · sql.js（SQLite 直连模式用）在 bundle 里是 external，SEA 单文件**不含**它；
//     因此桌面版「直连 SQLite」不可用（HTTP/HTTPS 扫描能力完整）。需要该模式时，
//     把 dist-engine/node_modules 作为 Tauri resource 随包分发，或把 wasm 走 SEA assets。
//
// 用法：
//   node scripts/build-sidecar.mjs              # 全流程：cjs bundle → blob → 注入 → 冒烟
//   node scripts/build-sidecar.mjs --skip-smoke # 跳过冒烟（调试用）
//   NODE_SEA_BASE=<path/to/node.exe> node scripts/build-sidecar.mjs   # 指定 base 运行时
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST_DIR = path.join(ROOT, 'server', 'dist-engine');
const BINARIES_DIR = path.join(ROOT, 'src-tauri', 'binaries');
const SEA_CONFIG = path.join(ROOT, 'sea-config.json');
const skipSmoke = process.argv.includes('--skip-smoke');

const log = (m) => console.log(`[build-sidecar] ${m}`);
const fail = (m) => {
  console.error(`[build-sidecar] ✗ ${m}`);
  process.exit(1);
};

// ── 目标三元组（与 Tauri externalBin 命名约定一致）──────────────────────────
function targetTriple() {
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  if (!arch) fail(`不支持的 CPU 架构：${process.arch}`);
  const osPart = { win32: 'pc-windows-msvc', darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  if (!osPart) fail(`不支持的操作系统：${process.platform}`);
  return `${arch}-${osPart}`;
}

const triple = targetTriple();
const exeName = `sqli-engine-${triple}${process.platform === 'win32' ? '.exe' : ''}`;
const exePath = path.join(BINARIES_DIR, exeName);

fs.mkdirSync(BINARIES_DIR, { recursive: true });

// ── 1) 确保 CJS bundle 存在且新鲜 ─────────────────────────────────────────────
const cjsEntry = path.join(DIST_DIR, 'engine.cjs');
const needBuild = (() => {
  if (!fs.existsSync(cjsEntry)) return true;
  const srcMtime = Math.max(
    fs.statSync(path.join(ROOT, 'server', 'index.js')).mtimeMs,
    fs.statSync(path.join(ROOT, 'server', 'src')).mtimeMs
  );
  return fs.statSync(cjsEntry).mtimeMs < srcMtime;
})();

if (needBuild) {
  log('生成 CJS bundle（node scripts/build-engine.mjs --format cjs）…');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'build-engine.mjs'), '--format', 'cjs'], {
    cwd: ROOT, stdio: 'inherit',
  });
  if (r.status !== 0) fail('CJS bundle 生成失败（先修 build-engine.mjs 的报错）');
} else {
  log(`复用已有 CJS bundle（${path.relative(ROOT, cjsEntry)}）`);
}

// ── 2) 生成 SEA blob ─────────────────────────────────────────────────────────
const blobPath = path.join(DIST_DIR, 'sea-prep.blob');
fs.writeFileSync(
  SEA_CONFIG,
  JSON.stringify(
    {
      main: path.relative(ROOT, cjsEntry).replace(/\\/g, '/'),
      output: path.relative(ROOT, blobPath).replace(/\\/g, '/'),
      disableExperimentalSEAWarning: true,
      useSnapshot: false,
      useCodeCache: false,
    },
    null,
    2
  ) + '\n',
  'utf-8'
);
{
  const r = spawnSync(process.execPath, ['--experimental-sea-config', SEA_CONFIG], { cwd: ROOT, stdio: 'inherit' });
  if (r.status !== 0 || !fs.existsSync(blobPath)) fail('SEA blob 生成失败');
  log(`SEA blob: ${path.relative(ROOT, blobPath)}（${(fs.statSync(blobPath).size / 1024 / 1024).toFixed(1)} MB）`);
}

// ── 3) 复制 base 运行时（本机 node.exe / node）────────────────────────────────
const baseNode = process.env.NODE_SEA_BASE || process.execPath;
if (!fs.existsSync(baseNode)) fail(`找不到 base 运行时：${baseNode}`);
fs.copyFileSync(baseNode, exePath);
log(`base 运行时：${baseNode} → ${exeName}`);

// ── 4) 注入 blob（postject）──────────────────────────────────────────────────
{
  const args = [
    exePath, 'NODE_SEA_BLOB', blobPath,
    '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
  ];
  // 优先用本地安装的 postject：`npx postject` 在本机（Windows + 含全角括号的用户目录）
  // 经 shell 解析会失败，而 devDependency 直接 node 调用没有这层转义问题，CI 也一致。
  const localCli = path.join(ROOT, 'node_modules', 'postject', 'dist', 'cli.js');
  log('注入 SEA blob（postject）…');
  let r;
  if (fs.existsSync(localCli)) {
    r = spawnSync(process.execPath, [localCli, ...args], { cwd: ROOT, stdio: 'inherit' });
  } else {
    log('未找到本地 postject，回退 npx（建议 npm i -D postject 以便离线/CI 复现）');
    r = spawnSync(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--yes', 'postject', ...args], {
      cwd: ROOT, stdio: 'inherit',
    });
  }
  if (r.status !== 0) {
    fail('postject 注入失败。常见原因：exe 被占用（先关掉正在运行的 sidecar）、postject 缺失');
  }
}
log(`sidecar 产物：${path.relative(ROOT, exePath)}（${(fs.statSync(exePath).size / 1024 / 1024).toFixed(1)} MB）`);

// ── 5) 冒烟：真的把 exe 跑起来（起服务 + token emit），否则等于没打包成功 ──────
if (skipSmoke) {
  log('已跳过冒烟（--skip-smoke）');
  process.exit(0);
}

const PORT = 45999;
const child = spawn(exePath, [], {
  env: { ...process.env, HOST: '127.0.0.1', PORT: String(PORT), SCAN_API_TOKEN_EMIT: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
  cwd: DIST_DIR, // 让外部依赖（sql.js 等 dist-engine/node_modules）仍可按相对路径解析
});
let out = '';
child.stdout.on('data', (d) => (out += d.toString()));
child.stderr.on('data', (d) => (out += d.toString()));

const alive = await new Promise((resolve) => {
  const deadline = Date.now() + 30000;
  const tick = () => {
    const q = http.get({ host: '127.0.0.1', port: PORT, path: '/api/health' }, (res) => {
      res.resume();
      if (res.statusCode === 200) return resolve(true);
      if (Date.now() > deadline) return resolve(false);
      setTimeout(tick, 300);
    });
    q.on('error', () => {
      if (Date.now() > deadline) return resolve(false);
      setTimeout(tick, 300);
    });
    q.setTimeout(900, () => q.destroy());
  };
  tick();
});

try { child.kill(); } catch { /* noop */ }

if (!alive) {
  console.error(out.slice(0, 800));
  fail('sidecar 冒烟失败：exe 起来了但没提供 /api/health（上面的输出是它的日志）');
}
if (!/ENGINE_TOKEN=[a-f0-9]{64}/.test(out)) {
  fail('sidecar 冒烟失败：未捕获到 ENGINE_TOKEN（桌面端前端会拿不到 token → 全部 401）');
}
log('✓ 冒烟通过：sidecar 可启动引擎、health=200、一次性 token 正常回传');
log('提示：Tauri 打包前确认 tauri.conf.json 的 bundle.externalBin 含 "binaries/sqli-engine"');

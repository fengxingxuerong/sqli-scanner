#!/usr/bin/env node
// ============================================================================
// scripts/build-portable.mjs —— [D142 2026-10-23] 免安装便携包组装（离线可跑）
//
// 为什么需要它：官方安装包（NSIS/WiX）要联网下载工具链，在无网/受限环境里产不出任何
// 可交付物；而 D139/D141 的便携包此前是**手工复制**出来的 —— 手工步骤 = 「文件存在≠能力存在」
// 的经典形态（下次谁都不会记得要改名 sidecar、要带 LICENSE）。
//
// 本脚本做四件事，任何一步不满足就**硬失败**（不静默降级）：
//   ① 校验两个输入产物存在：壳（release 构建产物）+ sidecar（SEA 产物）；
//   ② 按 Tauri 打包的命名约定落地：sidecar 必须改名成 `sqli-engine[.exe]`
//      （壳用 `shell().sidecar("sqli-engine")` 找它；不改名就跑不起来）；
//   ③ 带上 README / LICENSE；写 manifest.json（含每个文件的 sha256，便于交付核对）；
//   ④ 打 zip（zip 缺失就报错，不产半成品）。
//
// 用法：
//   node scripts/build-portable.mjs                     # 默认输出 dist-portable/
//   node scripts/build-portable.mjs --out <dir>         # 指定输出目录
//   node scripts/build-portable.mjs --no-zip            # 只出目录（调试用）
// 前置（任一条不满足会在报错里写明怎么补）：
//   npx tauri build --no-bundle        # 产出壳 exe
//   node scripts/build-sidecar.mjs     # 产出 sidecar exe
// ============================================================================
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name, dflt) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

/** 目标三元组（与 Tauri externalBin 命名约定一致；与 build-sidecar 同一张表） */
function targetTriple() {
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  const osPart = { win32: 'pc-windows-msvc', darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  if (!arch || !osPart) fail(`不支持的平台：${process.platform} ${process.arch}`);
  return `${arch}-${osPart}`;
}

/** 输出并退出（1 = 失败，与仓库其它门禁一致：失败必须非零） */
function fail(msg) {
  console.error(`[portable] ✗ ${msg}`);
  process.exit(1);
}

const EXT = process.platform === 'win32' ? '.exe' : '';
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const PLAT = `${process.platform}-${process.arch}`;
const OUT_DIR = path.resolve(opt('--out', path.join(ROOT, 'dist-portable', `sqli-v${VERSION}-portable-${PLAT}`)));

// ── ① 输入产物 ───────────────────────────────────────────────────────────────
const SHELL_EXE = path.join(ROOT, 'src-tauri', 'target', 'release', `sqli-scanner${EXT}`);
const SIDECAR_EXE = path.join(ROOT, 'src-tauri', 'binaries', `sqli-engine-${targetTriple()}${EXT}`);

if (!fs.existsSync(SHELL_EXE)) {
  fail(
    `找不到壳产物：${path.relative(ROOT, SHELL_EXE)}\n` +
      '  先跑：npx tauri build --no-bundle（本仓桌面壳 release 构建；无网也可跑）'
  );
}
if (!fs.existsSync(SIDECAR_EXE)) {
  fail(
    `找不到 sidecar 产物：${path.relative(ROOT, SIDECAR_EXE)}\n` +
      '  先跑：node scripts/build-sidecar.mjs（Node SEA 单文件引擎）'
  );
}

// ── ② 组装 ───────────────────────────────────────────────────────────────────
fs.rmSync(OUT_DIR, { recursive: true, force: true });
fs.mkdirSync(OUT_DIR, { recursive: true });

/** [Tauri 命名约定] sidecar 必须叫 `sqli-engine[.exe]`，否则壳按名找不到它 */
const SIDECAR_DST = path.join(OUT_DIR, `sqli-engine${EXT}`);
fs.copyFileSync(SHELL_EXE, path.join(OUT_DIR, `sqli-scanner${EXT}`));
fs.copyFileSync(SIDECAR_EXE, SIDECAR_DST);
for (const extra of ['README.md', 'LICENSE']) {
  const src = path.join(ROOT, extra);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(OUT_DIR, extra));
}

/** sha256：交付件要能逐个核对（与仓库「产物可复现」的口径一致） */
const sha256 = (p) => createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const files = fs
  .readdirSync(OUT_DIR)
  .sort()
  .map((name) => {
    const p = path.join(OUT_DIR, name);
    return { name, size: fs.statSync(p).size, sha256: sha256(p) };
  });

const manifest = {
  name: 'sqli-scanner',
  version: VERSION,
  kind: 'portable',
  platform: PLAT,
  builtAt: new Date().toISOString(),
  files,
  note: '免安装绿色包（不是官方安装包）：解压后直接运行 sqli-scanner[.exe]；sidecar 必须与它同目录且名为 sqli-engine[.exe]。',
};
fs.writeFileSync(path.join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

const mb = (n) => `${(n / 1024 / 1024).toFixed(1)} MB`;
console.log(`[portable] ✓ 组装完成：${path.relative(ROOT, OUT_DIR)}`);
for (const f of files) console.log(`  · ${f.name.padEnd(18)} ${mb(f.size).padStart(9)}  sha256=${f.sha256.slice(0, 12)}…`);
console.log(`  合计 ${mb(files.reduce((s, f) => s + f.size, 0))}`);

// ── ③ 打 zip（失败必须非零，不做半成品交付）───────────────────────────────────
if (flag('--no-zip')) {
  console.log('[portable] 已跳过打 zip（--no-zip）');
  process.exit(0);
}
const ZIP = `${OUT_DIR}.zip`;
fs.rmSync(ZIP, { force: true });
const r =
  process.platform === 'win32'
    ? spawnSync('powershell', ['-NoProfile', '-Command', `Compress-Archive -Path '${OUT_DIR}\\*' -DestinationPath '${ZIP}' -Force`], { stdio: 'inherit' })
    : spawnSync('zip', ['-qr', ZIP, '.'], { cwd: OUT_DIR, stdio: 'inherit' });
if (r.status !== 0 || !fs.existsSync(ZIP)) {
  fail(`打 zip 失败（exit=${r.status}）。Windows 用 Compress-Archive、其它平台需要 zip 命令；确保产物完整再交付。`);
}
console.log(`[portable] ✓ zip：${path.relative(ROOT, ZIP)}（${mb(fs.statSync(ZIP).size)}）`);
console.log('[portable] 下一步冒烟：node scripts/portable-smoke.mjs（干净解压 → 起壳 → 断言健康与版本）');
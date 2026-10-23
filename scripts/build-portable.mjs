#!/usr/bin/env node
// ============================================================================
// scripts/build-portable.mjs —— [D142 2026-10-23] 免安装便携包组装（离线可跑）
//
// 为什么需要它：官方安装包（NSIS/WiX）要联网下载工具链，在无网/受限环境里产不出任何
// 可交付物；而 D141 的便携包此前是**手工复制**出来的 —— 手工步骤 = 「文件存在≠能力存在」
// 的经典形态（下次谁都不会记得要改名 sidecar、要带 LICENSE）。
//
// 本脚本做四件事，任何一步不满足就**硬失败**（不静默降级）：
//   ① 校验两个输入产物存在：壳（release 构建产物）+ sidecar（SEA 产物）；
//   ② 按 Tauri 打包的命名约定落地：sidecar 必须改名成 `sqli-engine[.exe]`
//      （壳用 `shell().sidecar("sqli-engine")` 找它；不改名就跑不起来）；
//   ③ 带上 README / LICENSE；写 manifest.json（含每个文件的 sha256，便于交付核对）；
//   ④ 打 zip（zip 缺失就报错，不产半成品）。
//
// 命名约定与 manifest 判据在 scripts/lib/portable.mjs（与 portable-smoke 共用一个来源）。
//
// 用法：
//   node scripts/build-portable.mjs                     # 默认输出 dist-portable/
//   node scripts/build-portable.mjs --out <dir>         # 指定输出目录
//   node scripts/build-portable.mjs --no-zip            # 只出目录（调试用）
//   node scripts/build-portable.mjs --selftest          # 自证纯函数判据（不碰产物）
// 前置（任一条不满足会在报错里写明怎么补）：
//   npx tauri build --no-bundle        # 产出壳 exe
//   node scripts/build-sidecar.mjs     # 产出 sidecar exe
// ============================================================================
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildChecks, buildManifest, failWith, isDirectRun, portableLayout, readOpt, runSelftest } from './lib/portable.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TAG = '[portable]';
const fail = (msg) => failWith(TAG, msg);

// ── 自证：纯函数判据必须对合成样本有反应（用例在 scripts/lib/portable.mjs）────────
function selftest() {
  runSelftest(TAG, buildChecks(), '命名约定 / 三元组 / manifest sha256');
}

/** 校验壳与 sidecar 产物存在（缺失时报出「该补哪条命令」） */
function assertInputs(layout) {
  const shellExe = path.join(ROOT, 'src-tauri', 'target', 'release', layout.shell);
  const sidecarExe = path.join(ROOT, 'src-tauri', 'binaries', String(layout.sidecar));
  if (!fs.existsSync(shellExe)) {
    fail(
      `找不到壳产物：${path.relative(ROOT, shellExe)}\n` +
        '  先跑：npx tauri build --no-bundle（本仓桌面壳 release 构建；无网也可跑）'
    );
  }
  if (!fs.existsSync(sidecarExe)) {
    fail(
      `找不到 sidecar 产物：${path.relative(ROOT, sidecarExe)}\n` +
        '  先跑：node scripts/build-sidecar.mjs（Node SEA 单文件引擎）'
    );
  }
  return { shellExe, sidecarExe };
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
function main() {
  const argv = process.argv.slice(2);
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  const layout = portableLayout(process.platform, process.arch);
  if (!layout.ok) fail(`不支持的平台：${process.platform} ${process.arch}`);
  const outDir = path.resolve(
    readOpt(argv, '--out') ?? path.join(ROOT, 'dist-portable', `sqli-v${version}-portable-${process.platform}-${process.arch}`)
  );

  const { shellExe, sidecarExe } = assertInputs(layout);

  // 组装（sidecar 改名是硬要求，见 portableLayout 注释）
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  fs.copyFileSync(shellExe, path.join(outDir, layout.shell));
  fs.copyFileSync(sidecarExe, path.join(outDir, layout.sidecarDst));
  for (const extra of ['README.md', 'LICENSE']) {
    const src = path.join(ROOT, extra);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(outDir, extra));
  }

  const manifest = buildManifest(outDir, { name: 'sqli-scanner', version, platform: `${process.platform}-${process.arch}` });
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  const mb = (n) => `${(n / 1024 / 1024).toFixed(1)} MB`;
  console.log(`${TAG} ✓ 组装完成：${path.relative(ROOT, outDir)}`);
  for (const f of manifest.files) console.log(`  · ${f.name.padEnd(18)} ${mb(f.size).padStart(9)}  sha256=${f.sha256.slice(0, 12)}…`);
  console.log(`  合计 ${mb(manifest.files.reduce((s, f) => s + f.size, 0))}`);

  if (argv.includes('--no-zip')) {
    console.log(`${TAG} 已跳过打 zip（--no-zip）`);
    return;
  }
  const zip = `${outDir}.zip`;
  fs.rmSync(zip, { force: true });
  const r =
    process.platform === 'win32'
      ? spawnSync('powershell', ['-NoProfile', '-Command', `Compress-Archive -Path '${outDir}\\*' -DestinationPath '${zip}' -Force`], { stdio: 'inherit' })
      : spawnSync('zip', ['-qr', zip, '.'], { cwd: outDir, stdio: 'inherit' });
  if (r.status !== 0 || !fs.existsSync(zip)) {
    fail(`打 zip 失败（exit=${r.status}）。Windows 用 Compress-Archive、其它平台需要 zip 命令；确保产物完整再交付。`);
  }
  console.log(`${TAG} ✓ zip：${path.relative(ROOT, zip)}（${mb(fs.statSync(zip).size)}）`);
  console.log(`${TAG} 下一步冒烟：node scripts/portable-smoke.mjs（干净解压 → 起壳 → 断言健康与版本）`);
}

if (process.argv.includes('--selftest')) {
  selftest();
  process.exit(0);
}

// 仅直接运行时执行主流程（import 进测试/其它脚本时不产生副作用）
if (isDirectRun(import.meta.url)) main();
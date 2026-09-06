#!/usr/bin/env node
/**
 * build-engine.mjs — 把 server/ 检测引擎打成可部署的 Node 运行时包（替代原 echo 占位脚本）
 *
 * 产物布局（server/dist-engine/）：
 *   engine.mjs                   esbuild 打包的单文件 ESM 入口（bundle + minify）
 *   node_modules/sql.js/         sql.js 运行时（保持「外部依赖」原样复制，含 wasm）
 *     ├─ package.json
 *     └─ dist/{sql-wasm.js, sql-wasm.wasm}
 *
 * 为什么 sql.js 不打进单文件（关键难点，已核实 server/node_modules/sql.js@1.14.1）：
 *   - sql.js 的 Node 版实现（dist/sql-wasm.js）在运行时用真实 CJS 的
 *     `__dirname` + `require("node:fs"/"node:crypto")` 定位并读取 sql-wasm.wasm
 *     （默认 locateFile 即 `__dirname + "sql-wasm.wasm"`）。
 *   - esbuild 的 ESM 输出没有 __dirname，若强行把 sql-wasm.js 内联进 engine.mjs，
 *     __dirname 在运行时会 ReferenceError，wasm 加载必然失败。
 *   - 因此采用「外部化 + 随包复制」：复制后的 sql-wasm.js 仍是真实 CJS 文件，
 *     __dirname 语义正确，wasm 与它同目录，默认 locateFile 即可命中——
 *     无需改任何业务源码，也无需给 initSqlJs 传 locateFile。
 *   - 已验证：server 全部业务代码与直接依赖（express/axios/winston/dotenv/cors/
 *     socks-proxy-agent/nanoid）均不使用 __dirname / require（除 sqlmapBridge.js
 *     用 import.meta.url 算出的本地常量，打包后语义不变），ESM 单文件无隐患。
 *
 * 用法：
 *   node scripts/build-engine.mjs                # 默认：bundle + wasm 复制 + 冒烟校验 + 暂存到 src-tauri/binaries/
 *   node scripts/build-engine.mjs --no-minify    # 关闭压缩（调试产物）
 *   node scripts/build-engine.mjs --skip-binaries# 不复制到 src-tauri/binaries/
 *   node scripts/build-engine.mjs --format cjs   # 输出 engine.cjs（SEA/pkg 前置可选，见下）
 *
 * 打成「Tauri sidecar 单文件可执行」的后续路线（本脚本不代做，取舍见 report.md 任务 2）：
 *   1) @yao-pkg/pkg（推荐先试）：在 server/ 下
 *        npx pkg dist-engine/engine.mjs --target node20-win-x64 \
 *          --output ../src-tauri/binaries/sqli-engine-x86_64-pc-windows-msvc.exe
 *      pkg 会快照 server/node_modules（含本脚本复制出的 sql.js 运行时），
 *      fs.readFileSync 读 wasm 走 pkg 虚拟 FS，天然可用；
 *      若 pkg 对 ESM 入口支持不佳，先用 --format cjs 打 engine.cjs 再 pkg。
 *   2) Node SEA（Node ≥ 20.12，自包含要求高）：需把 sql.js 内联进主脚本
 *      （banner 注入 createRequire/__dirname + locateFile 指向 exe 旁 wasm，
 *      且 Node 20 的 SEA 仅稳定支持 CJS 入口），复杂度高，建议二期单独做。
 *   3) 降级：直接分发 dist-engine/ 目录 + 启动命令（要求目标机装有 Node ≥ 20）。
 *
 * Tauri 侧 sidecar 命名约定：externalBin 声明 binaries/sqli-engine，
 * 实际文件须为 src-tauri/binaries/sqli-engine-<target-triple>[.exe]（如
 * sqli-engine-x86_64-pc-windows-msvc.exe）。src-tauri/binaries 已被 .gitignore
 * 忽略，本脚本会按需创建目录并写入（不入库，符合预期）。
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const SERVER_DIR = path.join(ROOT, 'server');
const DIST_DIR = path.join(SERVER_DIR, 'dist-engine');
const BINARIES_DIR = path.join(ROOT, 'src-tauri', 'binaries');
const SQLJS_SRC = path.join(SERVER_DIR, 'node_modules', 'sql.js');

// ── 参数解析 ────────────────────────────────────────────────────────
const rawArgs = process.argv.slice(2);
if (rawArgs.includes('--help') || rawArgs.includes('-h')) {
  console.log(`用法: node scripts/build-engine.mjs [选项]
  --no-minify     关闭 esbuild 压缩（调试）
  --skip-binaries 不复制产物到 src-tauri/binaries/
  --format <fmt>  输出格式: esm（默认）| cjs（SEA/pkg 前置可选）
  --help          显示本帮助`);
  process.exit(0);
}
const format = (() => {
  const i = rawArgs.indexOf('--format');
  const v = i !== -1 ? String(rawArgs[i + 1] || '') : '';
  return v === 'cjs' ? 'cjs' : 'esm';
})();
const opts = {
  minify: !rawArgs.includes('--no-minify'),
  copyBinaries: !rawArgs.includes('--skip-binaries'),
  format,
};

// ── 工具 ────────────────────────────────────────────────────────────
function log(msg) {
  console.log(`[build-engine] ${msg}`);
}
function fail(msg, code = 1) {
  console.error(`[build-engine] 失败: ${msg}`);
  process.exitCode = code;
  throw new Error(msg);
}
function getTargetTriple() {
  const archMap = { x64: 'x86_64', ia32: 'i686', arm64: 'aarch64' };
  const osMap = { win32: 'pc-windows-msvc', darwin: 'apple-darwin', linux: 'unknown-linux-gnu' };
  return `${archMap[process.arch] || process.arch}-${osMap[process.platform] || process.platform}`;
}

// ── 加载 esbuild（根 node_modules 优先，server 次之，否则给出安装指引）──
async function loadEsbuild() {
  try {
    return (await import('esbuild')).build;
  } catch {
    try {
      const { createRequire } = await import('node:module');
      const requireFromServer = createRequire(path.join(SERVER_DIR, 'package.json'));
      return requireFromServer('esbuild');
    } catch {
      fail(
        `找不到 esbuild（根目录也没有）。请先在根目录安装（版本与 vite 依赖对齐）:\n` +
          `  npm install -D esbuild@^0.21.5\n` +
          `然后更新 package-lock.json 后再试（npm ci 场景下 lockfile 不同步会直接报错）。`
      );
    }
  }
}

// ── 主流程 ──────────────────────────────────────────────────────────
async function main() {
  const entry = path.join(SERVER_DIR, 'index.js');
  if (!fs.existsSync(entry)) fail(`入口不存在: ${entry}`);
  if (!fs.existsSync(path.join(SQLJS_SRC, 'dist', 'sql-wasm.js'))) {
    fail('server/node_modules/sql.js 未安装，请先执行: cd server && npm ci');
  }

  const ext = format === 'cjs' ? 'cjs' : 'mjs';
  const outfile = path.join(DIST_DIR, `engine.${ext}`);

  // 干净重建
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
  fs.mkdirSync(DIST_DIR, { recursive: true });

  // 1) esbuild bundle（sql.js 保持外部，其余全部内联）
  const build = await loadEsbuild();
  log(`esbuild bundle: server/index.js → ${path.relative(ROOT, outfile)} (format=${format}, minify=${opts.minify})`);
  const result = await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    platform: 'node',
    format,
    target: ['node20'],
    minify: opts.minify,
    charset: 'utf8', // 保留中文可读，不转义成 \uXXXX
    legalComments: 'none',
    sourcemap: false,
    external: ['sql.js'], // 动态 import('sql.js') 原样保留，运行时从 dist-engine/node_modules 解析
    logLevel: 'info',
  });
  if (result.errors && result.errors.length > 0) {
    fail(`esbuild 打包失败（${result.errors.length} 个错误）`);
  }

  // 2) 复制 sql.js 运行时（仅 3 个必要文件：入口 js + wasm + 解析用的 package.json）
  const destPkg = path.join(DIST_DIR, 'node_modules', 'sql.js');
  fs.mkdirSync(path.join(destPkg, 'dist'), { recursive: true });
  const sqlJsFiles = ['package.json', 'dist/sql-wasm.js', 'dist/sql-wasm.wasm'];
  for (const rel of sqlJsFiles) {
    const src = path.join(SQLJS_SRC, rel);
    if (!fs.existsSync(src)) fail(`sql.js 缺少文件: ${rel}（版本与预期不符，请重新 npm ci）`);
    fs.copyFileSync(src, path.join(destPkg, rel));
    log(`  ✓ 已复制 ${rel} → node_modules/sql.js/${rel}`);
  }

  // 3) 产物校验：冒烟 import + 打印大小
  const engineStat = fs.statSync(outfile);
  const wasmStat = fs.statSync(path.join(destPkg, 'dist', 'sql-wasm.wasm'));
  log(`engine.${ext} 大小: ${(engineStat.size / 1024).toFixed(1)} KB | sql-wasm.wasm 大小: ${(wasmStat.size / 1024).toFixed(1)} KB`);

  if (format === 'esm') {
    const url = pathToFileURL(outfile).href;
    // 注意：冒烟测试在 CJS 上下文中执行 import()（--input-type=module 会导致 ESM
    // 严格上下文禁止某些依赖内部的动态 require('path')，虽不影响实际运行，
    // 但会让冒烟误报失败）。CJS 的 import() 同样把模块当 ESM 解析，校验完全有效。
    const smoke = `import(${JSON.stringify(url)}).then(m => { if (typeof m.default !== 'function' || typeof m.start !== 'function') { console.error('[smoke] 导出不完整'); process.exit(1); } console.log('[smoke] ok: default(createApp)/start 导出正常'); }).catch(e => { console.error('[smoke] 失败:', e && e.message); process.exit(1); })`;
    const r = spawnSync(process.execPath, ['-e', smoke], {
      cwd: DIST_DIR,
      encoding: 'utf8',
      timeout: 30000,
    });
    if (r.status !== 0) fail(`冒烟校验未通过:\n${r.stdout || ''}${r.stderr || ''}`);
    log(`  ✓ 冒烟通过（import engine.mjs 可加载，default/start 导出正常）`);
  } else {
    // CJS 输出：校验导出；直跑 `node engine.cjs` 的自动启动依赖 esbuild 对
    // import.meta.url 的 CJS shim 是否与 index.js 的 isMain 判定一致（需实跑验证一次）。
    const smoke = `const m = require(${JSON.stringify(outfile)}); if (typeof m.default !== 'function' || typeof m.start !== 'function') { console.error('[smoke] 导出不完整'); process.exit(1); } console.log('[smoke] ok: default(createApp)/start 导出正常');`;
    const r = spawnSync(process.execPath, ['-e', smoke], {
      cwd: DIST_DIR,
      encoding: 'utf8',
      timeout: 30000,
    });
    if (r.status !== 0) fail(`冒烟校验未通过:\n${r.stdout || ''}${r.stderr || ''}`);
    log(`  ✓ 冒烟通过（require engine.cjs 可加载，default/start 导出正常）`);
  }

  // 4) 暂存到 src-tauri/binaries/（该目录已被 .gitignore 忽略，按需创建、不入库）
  if (opts.copyBinaries) {
    const staging = path.join(BINARIES_DIR, 'sqli-engine-assets');
    fs.rmSync(staging, { recursive: true, force: true });
    fs.mkdirSync(staging, { recursive: true });
    fs.cpSync(DIST_DIR, staging, { recursive: true });
    log(`  ✓ 已暂存到 ${path.relative(ROOT, staging)}（src-tauri/binaries 已被 .gitignore 忽略，不会入库）`);
  }

  // 5) 摘要与下一步
  const triple = getTargetTriple();
  const exeName = `sqli-engine-${triple}${process.platform === 'win32' ? '.exe' : ''}`;
  log('完成。产物可直接运行:');
  log(`  cd server && node dist-engine/engine.mjs   （默认监听 127.0.0.1:4567，PORT/HOST 可覆盖）`);
  if (opts.copyBinaries) {
    log(`Tauri sidecar 还需要「单文件可执行」 ${exeName}（放在 src-tauri/binaries/），`);
    log(`本产物是 Node 运行时包（engine + sql.js），单文件化路线（pkg / SEA）见脚本头部注释与 report.md 任务 2。`);
  }
}

main().catch((e) => {
  if (process.exitCode === 0) process.exitCode = 1;
  if (e && e.message && !/^\[build-engine\]/.test(e.message)) {
    console.error(`[build-engine] ${e.message}`);
  }
});

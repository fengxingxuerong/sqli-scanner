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
// sql.js / SQLite 直连模式（B1，2026-09-18 实测打通）：
//   SEA 的模块解析被劫持为「只认内建模块」，`require('sql.js')` 抛
//   "No such built-in module: sql.js"，`NODE_PATH` 也无效 —— 所以走**全内联**：
//     a) esbuild `--inline-sqljs`：sql-wasm.js 打进 bundle（不再 external）；
//     b) sql-wasm.wasm 作为 **SEA asset** 内嵌（见下方 assets 字段）；
//     c) 运行时 core/sqlJsLoader.js 用 node:sea 的 getAsset 取出，经
//        initSqlJs({ wasmBinary }) 直喂 —— sql.js 一收到 wasmBinary 就跳过
//        `__dirname + readFileSync`，因此不需要任何外部文件。
//   实测验证：把 exe 丢进**完全空目录**运行，真 SQLite 建表/查询正常
//   （对照实验见 .workbuddy/memory/2026-09-18.md）。
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
// sql.js 的 wasm 源文件（内联进 SEA asset 用）
const SQLJS_WASM_SRC = path.join(ROOT, 'server', 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm');

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

// ── 0) 前置断言：SEA asset 键名与运行时读取键必须一致 ─────────────────────────
// 这里失配是**静默的**：exe 照常构建、照常启动，只有切到 SQLite 直连模式才回退
// 内存自检驱动（表现为"扫了但结果是假的"）。所以在构建期硬断言，别留到运行期。
{
  const loaderSrc = fs.readFileSync(path.join(ROOT, 'server', 'src', 'core', 'sqlJsLoader.js'), 'utf8');
  const m = loaderSrc.match(/SQL_WASM_ASSET\s*=\s*['"]([^'"]+)['"]/);
  if (!m) fail('无法从 server/src/core/sqlJsLoader.js 解析 SQL_WASM_ASSET，构建侧断言失效，请先修加载器');
  const loaderKey = m[1];
  if (loaderKey !== 'sql-wasm.wasm') {
    fail(
      `SEA asset 键名失配：sqlJsLoader.js 期望 "${loaderKey}"，` +
        `但 build-sidecar 注入的是 "sql-wasm.wasm" → 桌面直连 SQLite 会静默回退。请同步二者。`
    );
  }
  log(`✓ asset 键名一致性检查通过（${loaderKey}）`);
}

// ── 0b) 前置断言：tauri.conf.json 不得声明 sql.js 相关的 bundle.resources ──────
// B1 的达成方式是「sql.js 全内联」（sql-wasm.js 进 bundle + wasm 进 SEA asset），
// 因此**不需要**也不应该**把 node_modules 作为 Tauri resource 随包分发 ——
// 多一份资源目录只是徒增体积与"两份依赖可能不同步"的风险。
// 若有人日后为图省事又加了 resources，这条断言会立刻提醒他先读 sqlJsLoader.js。
{
  const confPath = path.join(ROOT, 'src-tauri', 'tauri.conf.json');
  if (!fs.existsSync(confPath)) fail(`找不到 ${path.relative(ROOT, confPath)}`);
  const conf = JSON.parse(fs.readFileSync(confPath, 'utf8'));
  const resources = conf?.bundle?.resources;
  const flat = Array.isArray(resources)
    ? resources
    : resources && typeof resources === 'object'
      ? Object.values(resources).flat()
      : [];
  const suspicious = flat.filter((r) => /sql\.js|node_modules|engine-deps/i.test(String(r)));
  if (suspicious.length) {
    fail(
      `tauri.conf.json 的 bundle.resources 声明了 sql.js 相关资源：${suspicious.join(', ')}。\n` +
        `  B1 已改为「全内联」方案（见 server/src/core/sqlJsLoader.js 头部），不需要随包分发依赖；\n` +
        `  如确要改回外部依赖方案，请先更新 sqlJsLoader 与 build-sidecar 并重跑冒烟。`
    );
  }
  // externalBin 仍必须声明 sidecar，否则 tauri build 不会把 exe 打进包
  const extBin = conf?.bundle?.externalBin;
  const hasSidecar = Array.isArray(extBin) && extBin.some((b) => /sqli-engine/.test(String(b)));
  if (!hasSidecar) {
    fail('tauri.conf.json 的 bundle.externalBin 缺少 "binaries/sqli-engine" → 打包后壳找不到 sidecar');
  }
  log('✓ Tauri bundle 配置检查通过（externalBin 已声明、无多余的 sql.js resources）');
}

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
  log('生成 CJS bundle（node scripts/build-engine.mjs --format cjs --inline-sqljs）…');
  // [B1] 必须带 --inline-sqljs：SEA 里外部 require('sql.js') 会抛 No such built-in module。
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'scripts', 'build-engine.mjs'), '--format', 'cjs', '--inline-sqljs'],
    { cwd: ROOT, stdio: 'inherit' }
  );
  if (r.status !== 0) fail('CJS bundle 生成失败（先修 build-engine.mjs 的报错）');
} else {
  log(`复用已有 CJS bundle（${path.relative(ROOT, cjsEntry)}）`);
}

// ── 2) 生成 SEA blob（含 sql.js wasm asset）───────────────────────────────────
const blobPath = path.join(DIST_DIR, 'sea-prep.blob');
// wasm 源优先用 dist-engine 下的（build-engine 已按 --inline-sqljs 输出一份），
// 回退到 server/node_modules（例如复用了旧 bundle 时 dist-engine 里可能没有）。
const wasmForAsset = fs.existsSync(path.join(DIST_DIR, 'sql-wasm.wasm'))
  ? path.join(DIST_DIR, 'sql-wasm.wasm')
  : SQLJS_WASM_SRC;
if (!fs.existsSync(wasmForAsset)) {
  fail(`找不到 sql-wasm.wasm：${wasmForAsset}（请先 cd server && npm ci）`);
}
fs.writeFileSync(
  SEA_CONFIG,
  JSON.stringify(
    {
      main: path.relative(ROOT, cjsEntry).replace(/\\/g, '/'),
      output: path.relative(ROOT, blobPath).replace(/\\/g, '/'),
      disableExperimentalSEAWarning: true,
      useSnapshot: false,
      useCodeCache: false,
      // [B1] 把 wasm 作为 SEA asset 内嵌：运行时 core/sqlJsLoader.js 用
      // require('node:sea').getAsset('sql-wasm.wasm') 取出后喂给 initSqlJs({ wasmBinary })。
      // 键名必须与 sqlJsLoader.js 的 SQL_WASM_ASSET 一致（现已加断言校验）。
      assets: {
        'sql-wasm.wasm': path.relative(ROOT, wasmForAsset).replace(/\\/g, '/'),
      },
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
  log(`  内嵌 asset: sql-wasm.wasm（${(fs.statSync(wasmForAsset).size / 1024).toFixed(1)} KB）← ${path.relative(ROOT, wasmForAsset)}`);
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

// ── 5) 冒烟：真的把 exe 跑起来（起服务 + token emit + 直连 SQLite 真扫）────────
// 关键：cwd 用**全新空目录**，模拟 Tauri 把 exe 放到资源目录、旁边没有任何依赖的场景。
// 若 exe 仍依赖外部 sql.js，这里就会暴露（旧版正是靠 cwd=DIST_DIR 掩盖了这个问题）。
if (skipSmoke) {
  log('已跳过冒烟（--skip-smoke）');
  process.exit(0);
}

const PORT = 45999;
const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqli-sidecar-smoke-'));
log(`冒烟 cwd（空目录，验证零外部依赖）：${emptyDir}`);

const child = spawn(exePath, [], {
  env: { ...process.env, HOST: '127.0.0.1', PORT: String(PORT), SCAN_API_TOKEN_EMIT: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
  cwd: emptyDir,
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

if (!alive) {
  try { child.kill(); } catch { /* noop */ }
  console.error(out.slice(0, 800));
  fail('sidecar 冒烟失败：exe 起来了但没提供 /api/health（上面的输出是它的日志）');
}

const tokenMatch = out.match(/ENGINE_TOKEN=([a-f0-9]{64})/);
if (!tokenMatch) {
  try { child.kill(); } catch { /* noop */ }
  fail('sidecar 冒烟失败：未捕获到 ENGINE_TOKEN（桌面端前端会拿不到 token → 全部 401）');
}
const token = tokenMatch[1];
log('✓ 引擎启动、health=200、一次性 token 已回传');

// ── 5b) 直连 SQLite 真扫（B1 的核心验收）────────────────────────────────────
// 起真实 sqlite 库（driverType=sqljs + initSql 建表），跑一次直连扫描。
// 判定依据用 **SSE 事件**而非轮询报告：实测直连扫描亚秒级完成，而 getReport 在
// 扫描终结 + retireTtlMs(TTL) 到期后就回收（"扫描不存在或已结束"），轮询很容易扑空；
// 且报告刚创建时字段尚未填充。scan_completed / scan_error 是权威终结信号。
const INIT_SQL = [
  'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT);',
  "INSERT INTO users VALUES (1, '张三', 'zhangsan@example.com', 'pass123');",
  "INSERT INTO users VALUES (2, '李四', 'lisi@example.com', 'secret456');",
].join('\n');

function post(pathname, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path: pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          'x-api-token': token,
        },
      },
      (res) => {
        let buf = '';
        res.on('data', (c) => (buf += c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, json: JSON.parse(buf) }); }
          catch { resolve({ status: res.statusCode, json: null, raw: buf.slice(0, 300) }); }
        });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/** 订阅 SSE 直到扫描终结，返回 { events, terminal, report } */
function watchScanEvents(scanId, timeoutMs = 60000) {
  return new Promise((resolve) => {
    const events = [];
    let terminal = null;
    let report = null;
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve({ events, terminal, report });
    };
    const req = http.get(
      { host: '127.0.0.1', port: PORT, path: `/api/scan/${scanId}/events?token=${token}` },
      (res) => {
        res.on('data', (chunk) => {
          for (const line of String(chunk).split('\n')) {
            if (!line.startsWith('data:')) continue;
            let evt;
            try { evt = JSON.parse(line.slice(5)); } catch { continue; }
            events.push(evt.type);
            if (['scan_completed', 'scan_error', 'scan_stopped'].includes(evt.type)) {
              terminal = evt.type;
              report = evt.payload || null;
              try { req.destroy(); } catch { /* noop */ }
              return done();
            }
          }
        });
        res.on('end', done);
      }
    );
    req.on('error', done);
    setTimeout(() => { try { req.destroy(); } catch { /* noop */ } done(); }, timeoutMs);
  });
}

let directOk = false;
let directMsg = '';
try {
  const started = await post('/api/scan/start', {
    mode: 'direct',
    db: { driverType: 'sqljs', initSql: INIT_SQL },
    sqlTemplate: 'SELECT * FROM users WHERE id={INJECT}',
    originalValue: '1',
  });
  const scanId = started.json?.data?.scanId;
  if (!scanId) {
    directMsg = `启动直连扫描失败：HTTP ${started.status} ${JSON.stringify(started.json || started.raw)}`;
  } else {
    const { events, terminal, report } = await watchScanEvents(scanId);
    // 关键：识别「静默回退到内存自检驱动」——内存驱动也能产出 detection_found，
    // 所以必须看引擎日志有没有回退告警（dbDrivers.js 在 sql.js 加载失败时打这条）。
    const fellBack = /回退到内存自检驱动/.test(out);
    const foundCount = events.filter((t) => t === 'detection_found').length;

    if (terminal !== 'scan_completed') {
      directMsg = `直连扫描未正常完成：terminal=${terminal || '超时'}，事件=${events.join('>') || '无'}`;
    } else if (fellBack) {
      directMsg = 'sql.js 加载失败并回退内存驱动（引擎日志出现回退告警）→ SEA 内联未生效';
    } else if (foundCount < 1) {
      directMsg = `扫描完成但 detection_found=0（事件=${events.join('>')}）→ sql.js 可能未真正执行`;
    } else {
      const pts = report?.points || report?.vulnerablePoints || [];
      directOk = true;
      log(`✓ 直连 SQLite 真扫通过：detection_found=${foundCount}，报告 points=${pts.length}，事件链=${events.join('>')}`);
    }
  }
} catch (e) {
  directMsg = `直连扫描异常：${e && e.message}`;
}

try { child.kill(); } catch { /* noop */ }
try { fs.rmSync(emptyDir, { recursive: true, force: true }); } catch { /* noop */ }

if (!directOk) {
  console.error(out.slice(0, 1500));
  fail(`sidecar 直连 SQLite 冒烟失败：${directMsg}`);
}
log('✓ 冒烟通过：引擎启动 + health=200 + 一次性 token + SEA 内联的 SQLite 直连真扫');
log('提示：Tauri 打包前确认 tauri.conf.json 的 bundle.externalBin 含 "binaries/sqli-engine"');

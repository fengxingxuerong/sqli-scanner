#!/usr/bin/env node
// ============================================================================
// scripts/labs.mjs —— [D144 2026-10-23] 本机靶场体检 / 拉起 / 收工（25 套件全绿的外部依赖）
//
// 为什么需要它：全量验收 25/25 依赖 6 个外部服务，而起法此前只活在 TODO 的散文里、路径是本机硬编码。
// 危险不只是「麻烦」：**没起来的靶场在验收里表现为 SKIP/BLOCKED**，很容易被读成「没问题」。
// 本脚本把「哪些起了、哪些没起、为什么没起、要设哪个环境变量」变成一条命令的输出。
//
// 用法：
//   node scripts/labs.mjs                 # --check：体检（只探测，不起进程）
//   node scripts/labs.mjs --require=dvwa,juice   # 体检并把指定靶场变硬要求（没起即 exit 1）
//   node scripts/labs.mjs --up            # 把「前置齐备且端口没起」的靶场拉起来
//   node scripts/labs.mjs --up=mariadb,dvwa      # 只拉起指定靶场
//   node scripts/labs.mjs --stop          # 只杀**本脚本自己起过的**进程（pid 记在状态文件里）
//   node scripts/labs.mjs --list          # 打印配方（命令 + 前置 + 覆盖用的环境变量）
//   node scripts/labs.mjs --migrate       # [D190] 旧 %TEMP%\verify-labs 供应物迁移 dry-run（--apply 实迁）
//   node scripts/labs.mjs --selftest      # 自证纯函数判据（不起进程）
// 覆盖：所有路径都可用环境变量替换（MARIADB_HOME / PHP_EXE / DVWA_DIR / VAMPI_VENV / VAMPI_SRC /
//       NODE22_EXE / JUICE_DIR / JAVA_EXE / MAVEN_CMD / HSQL_JAR / BENCHMARK_DIR），见 --list。
// ============================================================================
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hasFlag, isDirectRun, readOpt, runSelftest } from './lib/portable.mjs';
import { labSpecs, planAll, renderRows, judgeLabs, selectToStart } from './lib/labs.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TAG = '[labs]';
const STATE_FILE = path.join(ROOT, '.box-agent-scratch', 'labs-pids.json');

/** 并发探端口（planLab 要同步判据，所以先探好再交给纯函数） */
function probePorts(ports) {
  return Promise.all(
    [...new Set(ports)].map(
      (port) =>
        new Promise((resolve) => {
          const s = net.connect({ port, host: '127.0.0.1' });
          const done = (open) => { s.destroy(); resolve([port, open]); };
          s.setTimeout(900, () => done(false));
          s.once('connect', () => done(true));
          s.once('error', () => done(false));
        })
    )
  ).then((pairs) => new Map(pairs));
}

/** 等某个端口就绪（拉起后用它确认真的起来了） */
async function waitPort(port, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const open = (await probePorts([port])).get(port);
    if (open) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/**
 * [D188] 端口就绪后调用靶场的播种端点（VAmPI 的 `/createdb`）。
 * 为什么必须自动做：官方 app.py 只建空 SQLite；不播种时 `/users/v1/name1` 返回 500，
 * 外部裁判要么判「靶场不可达」要么在 Node 24 undici 解析 500 断连时直接崩（2026-10-28 实测）。
 * @param {{port:number, seedPath:string}} lab
 * @returns {Promise<boolean>} 2xx 才算播种成功
 */
function seedLab(lab) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: lab.port, path: lab.seedPath, timeout: 20000 },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode >= 200 && res.statusCode < 300));
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

/** 读状态文件（记录本脚本起过哪些 pid，`--stop` 据此精确收工） */
function loadState() {
  try {
    const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    return Array.isArray(j.started) ? j : { started: [] };
  } catch {
    return { started: [] };
  }
}

/** 记一条「这个 pid 是我们起的」 */
function appendState(entry) {
  const st = loadState();
  st.started.push(entry);
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(st, null, 2) + '\n', 'utf8');
}

/** 拉起一个靶场（detached + 日志落盘，便于失败时取证） */
async function startLab(lab) {
  const logDir = path.join(ROOT, '.box-agent-scratch', 'labs-logs');
  fs.mkdirSync(logDir, { recursive: true });
  const out = fs.openSync(path.join(logDir, `${lab.id}.log`), 'w');
  // Windows 上 .cmd/.bat 不能由 spawn 直接执行（Node 24 直接抛 EINVAL），必须过 shell。
  // 本仓只有 mvn.cmd 走这里；其余都是 .exe / 解释器，保持直接 spawn 以免参数被 shell 重解析。
  const useShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(lab.cmd);
  let child;
  try {
    child = spawn(lab.cmd, lab.args ?? [], {
      cwd: lab.cwd,
      env: { ...process.env, ...(lab.env ?? {}) },
      detached: true,
      stdio: ['ignore', out, out],
      shell: useShell,
      windowsHide: true,
    });
  } catch (err) {
    fs.closeSync(out);
    return { up: false, pid: null, error: err.message };
  }
  if (!child.pid) {
    fs.closeSync(out);
    return { up: false, pid: null, error: 'spawn 未返回 pid' };
  }
  child.unref();
  appendState({ id: lab.id, pid: child.pid, startedAt: new Date().toISOString(), log: path.join('labs-logs', `${lab.id}.log`) });
  const timeoutMs = lab.startTimeoutMs ?? 45000;
  const up = await waitPort(lab.port, timeoutMs);
  if (up && lab.seedPath) {
    const seeded = await seedLab(lab);
    if (!seeded) return { up: false, pid: child.pid, error: `播种 ${lab.seedPath} 失败（看日志）` };
    console.log(`${TAG} ✓ ${lab.id} 已播种 ${lab.seedPath}`);
  }
  return { up, pid: child.pid, timeoutMs };
}

/** 收工：只杀状态文件里记着的 pid（不碰别人的进程） */
function stopLabs() {
  const st = loadState();
  if (!st.started.length) {
    console.log(`${TAG} 状态文件里没有本脚本起过的进程（${path.relative(ROOT, STATE_FILE)}）`);
    return 0;
  }
  for (const e of st.started) {
    try {
      process.kill(e.pid);
      console.log(`${TAG} 已停 ${e.id} pid=${e.pid}`);
    } catch {
      console.log(`${TAG} ${e.id} pid=${e.pid} 已不在（跳过）`);
    }
  }
  fs.rmSync(STATE_FILE, { force: true });
  return 0;
}

// ── [D190] 旧供应物迁移（D188 遗留 TODO）──────────────────────────────────────
// D188 把靶场供应物默认落点从 %TEMP%\verify-labs 迁到仓内 .verify-labs（耐久），但
// 「已供应在旧位置的机器怎么搬」没做——本组函数补上：规划（纯函数）+ 应用（copy→校验→才删源）。

/**
 * 规划迁移：旧目录里的每个条目，仓内没有 ⇒ move；两边都有 ⇒ keep-both
 * （解析顺序 env > 仓内 > TEMP，仓内副本优先，旧件不动也不删）。
 * @param {{sourceDir: string, destDir: string}} dirs 源（旧默认 %TEMP%\verify-labs）与目标（仓内 .verify-labs）
 * @param {{pathExists: (p: string) => boolean, readDir: (p: string) => string[]}} io 可注入 I/O（自证用合成实现）
 * @returns {{entries: Array<{entry: string, action: 'move'|'keep-both'}>, sourceMissing: boolean}}
 */
function planMigration({ sourceDir, destDir }, io) {
  if (!io.pathExists(sourceDir)) return { entries: [], sourceMissing: true };
  const entries = [];
  for (const entry of io.readDir(sourceDir)) {
    const action = io.pathExists(path.join(destDir, entry)) ? 'keep-both' : 'move';
    entries.push({ entry, action });
  }
  return { entries, sourceMissing: false };
}

/**
 * 执行迁移：copy → 校验落点存在 → 才删源（任何一步失败即中止该条并计入 failed，不碰其余条目）。
 * @param {{sourceDir: string, destDir: string}} dirs 同 planMigration
 * @param {{entry: string, action: string}[]} plan planMigration 产物（只处理 action='move' 的条目）
 * @param {{copy: (a: string, b: string) => void, rm: (p: string) => void, pathExists: (p: string) => boolean, join: (a: string, b: string) => string}} io 可注入 I/O
 * @returns {{moved: string[], failed: string[]}}
 */
function applyMigration({ sourceDir, destDir }, plan, io) {
  const moved = [];
  const failed = [];
  for (const { entry, action } of plan) {
    if (action !== 'move') continue;
    try {
      io.copy(io.join(sourceDir, entry), io.join(destDir, entry));
      if (!io.pathExists(io.join(destDir, entry))) throw new Error('copy 后落点不存在');
      io.rm(io.join(sourceDir, entry));
      moved.push(entry);
    } catch (e) {
      console.error(`${TAG} ✗ 迁移 ${entry} 失败：${String(e?.message || e).slice(0, 120)}`);
      failed.push(entry);
    }
  }
  return { moved, failed };
}

/** 打印配方（含所有可覆盖的环境变量名） */
function listRecipes(labs) {
  for (const lab of labs) {
    console.log(`\n${lab.id}（:${lab.port}）—— ${lab.title}`);
    if (lab.probeOnly) {
      console.log('  仅探测：本仓库不负责拉起');
      continue;
    }
    const envKeys = Object.keys(lab.env ?? {});
    console.log(`  cmd : ${lab.cmd}`);
    console.log(`  args: ${(lab.args ?? []).join(' ')}`);
    console.log(`  cwd : ${lab.cwd}`);
    if (envKeys.length) console.log(`  env : ${envKeys.map((k) => `${k}=${lab.env[k]}`).join(' ')}`);
    const hints = (lab.requires ?? []).map((r) => r.hint ?? r.path);
    if (hints.length) console.log(`  前置: ${hints.join(' · ')}`);
  }
}

/** 自证：体检判据必须对合成样本有反应 */
function selftest(labs) {
  const rowsUp = planAll(labs, { portOpen: () => true, pathExists: () => true });
  const rowsMissing = planAll(labs, { portOpen: () => false, pathExists: () => false });
  const rowsReady = planAll(labs, { portOpen: () => false, pathExists: () => true });
  const render = renderRows(rowsReady);
  runSelftest(TAG, [
    ['端口在监听一律判 up（复用，不重复拉起）', rowsUp.every((r) => r.status === 'up')],
    ['前置缺失一律 skip 且给出环境变量提示', rowsMissing.every((r) => r.status === 'skip' || r.status === 'probe-only')],
    ['缺前置时必须点名 missingPath', rowsMissing.some((r) => r.missingPath && r.missingPath.includes('环境变量'))],
    ['前置齐备且端口没起 ⇒ start', rowsReady.filter((r) => r.status === 'start').length >= 6],
    ['probe-only 项（PostgreSQL）绝不进入 start', rowsReady.filter((r) => r.status === 'probe-only').every((r) => r.id === 'postgres')],
    ['渲染结果含每个 id（漏一行就等于看不见）', labs.every((l) => render.includes(l.id))],
    ['--up 的 id 白名单能筛出待拉起项', selectToStart(labs, rowsReady, 'dvwa').todo.map((l) => l.id).join(',') === 'dvwa'],
    ['不认识的 id 必须被点名', selectToStart(labs, rowsReady, 'nope').unknown.join(',') === 'nope'],
    // [D148] `--require` 的判据（与 acceptance 的 `--require-labs` 共用同一份）
    ['require：全部在线 ⇒ ok', judgeLabs(rowsUp, ['dvwa', 'juice']).ok === true],
    ['require：没起的（含「可拉起但没起」）必须点名', judgeLabs(rowsReady, ['dvwa']).missing.join(',') === 'dvwa'],
    ['require：不认识的 id 与没起的分开报', judgeLabs(rowsUp, ['nope']).unknown.join(',') === 'nope'],
  ], '体检 / 筛选 / 渲染 / 硬要求 四类判据');

  // [D190] 迁移判据（纯函数 + 可注入 I/O；合成目录自证 move/keep-both/零副作用）
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'labs-migrate-selftest-'));
  try {
    const src = path.join(tmpRoot, 'old');
    const dst = path.join(tmpRoot, 'new');
    fs.mkdirSync(path.join(src, 'DVWA-master'), { recursive: true });
    fs.mkdirSync(path.join(src, 'VAmPI-master'), { recursive: true });
    fs.mkdirSync(path.join(dst, 'DVWA-master'), { recursive: true });
    const io = { pathExists: (p) => fs.existsSync(p), readDir: (p) => fs.readdirSync(p) };
    const plan = planMigration({ sourceDir: src, destDir: dst }, io);
    const caseKeepBoth = plan.entries.find((e) => e.entry === 'DVWA-master')?.action === 'keep-both';
    const caseMove = plan.entries.find((e) => e.entry === 'VAmPI-master')?.action === 'move';
    const caseMissing = planMigration({ sourceDir: path.join(tmpRoot, 'nope'), destDir: dst }, io).sourceMissing === true;
    const { moved, failed } = applyMigration({ sourceDir: src, destDir: dst }, plan.entries, {
      copy: (a, b) => fs.cpSync(a, b, { recursive: true }),
      rm: (p) => fs.rmSync(p, { recursive: true, force: true }),
      pathExists: (p) => fs.existsSync(p),
      join: path.join,
    });
    runSelftest(TAG, [
      ['同名条目判 keep-both（仓内优先），新条目判 move', caseKeepBoth === true && caseMove === true],
      ['源目录不存在 ⇒ sourceMissing 且零动作', caseMissing === true],
      ['apply：move 条目落点存在且源已删', moved.join(',') === 'VAmPI-master' && !fs.existsSync(path.join(src, 'VAmPI-master')) && fs.existsSync(path.join(dst, 'VAmPI-master'))],
      ['apply：零失败（keep-both 条目不被触碰）', failed.length === 0 && fs.existsSync(path.join(src, 'DVWA-master'))],
    ], '迁移规划 / 应用');
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
/** [D191] 旧供应物迁移：--migrate（默认 dry-run，--apply 实迁；--migrate-from 覆盖源目录） */
function runMigration(argv) {
  const sourceDir = readOpt(argv, '--migrate-from') || path.join(os.tmpdir(), 'verify-labs');
  const destDir = path.join(ROOT, '.verify-labs');
  const plan = planMigration({ sourceDir, destDir }, {
    pathExists: (p) => fs.existsSync(p),
    readDir: (p) => fs.readdirSync(p),
  });
  if (plan.sourceMissing) {
    console.log(`${TAG} 旧供应物目录不存在（${sourceDir}），无需迁移。`);
    return;
  }
  console.log(`${TAG} 迁移规划（源=${sourceDir} → 目标=${destDir}）：`);
  for (const { entry, action } of plan.entries) {
    console.log(`  ${action === 'move' ? '→ move     ' : '  keep-both '} ${entry}`);
  }
  if (!hasFlag(argv, '--apply')) {
    console.log(`${TAG} dry-run 预览。确认后加 --apply 实际迁移（copy 成功并校验落点后才删源）。`);
    return;
  }
  const { moved, failed } = applyMigration({ sourceDir, destDir }, plan.entries, {
    copy: (a, b) => fs.cpSync(a, b, { recursive: true }),
    rm: (p) => fs.rmSync(p, { recursive: true, force: true }),
    pathExists: (p) => fs.existsSync(p),
    join: path.join,
  });
  console.log(`${TAG} ✓ 已迁移 ${moved.length} 个：${moved.join(', ') || '（无）'}`);
  if (failed.length) {
    console.error(`${TAG} ✗ ${failed.length} 个失败：${failed.join(', ')}`);
    process.exit(1);
  }
}

/** [D144] 体检输出 + --require 硬要求判定（没起即 exit 1） */
async function printHealthAndRequire(labs, rows, argv) {
  console.log(`${TAG} 靶场体检（只探测，不起进程）：`);
  console.log(renderRows(rows));
  const require = readOpt(argv, '--require');
  if (!require) return;
  const ids = require.split(',').map((s) => s.trim()).filter(Boolean);
  const verdict = judgeLabs(rows, ids);
  if (verdict.unknown.length) {
    console.error(`\n${TAG} ✗ 不认识的靶场 id：${verdict.unknown.join(', ')}（用 --list 看可用 id）`);
    process.exit(1);
  }
  if (!verdict.ok) {
    console.error(`\n${TAG} ✗ --require 指定的靶场没起：${verdict.missing.join(', ')}`);
    console.error(`${TAG}   处置：node scripts/labs.mjs --up=${verdict.missing.join(',')}（或按 --list 里的配方手工起）`);
    process.exit(1);
  }
  console.log(`\n${TAG} ✓ --require 指定的靶场均在监听`);
}

/** [D144] 把选定靶场逐个拉起，全部就绪返回 true，任何失败打日志后返回 false */
async function startSelectedLabs(todo) {
  console.log(`${TAG} 准备拉起 ${todo.length} 个：${todo.map((l) => l.id).join(', ')}`);
  const failed = [];
  for (const lab of todo) {
    console.log(`${TAG} 启动 ${lab.id} …（日志 .box-agent-scratch/labs-logs/${lab.id}.log）`);
    const { up, pid, error, timeoutMs } = await startLab(lab);
    if (up) console.log(`${TAG} ✓ ${lab.id} 就绪（pid=${pid}）`);
    else {
      const why = error ? `启动失败：${error}` : `${Math.round((timeoutMs ?? 45000) / 1000)}s 内未就绪（pid=${pid}）`;
      console.error(`${TAG} ✗ ${lab.id} ${why} —— 看 .box-agent-scratch/labs-logs/${lab.id}.log`);
      failed.push(lab.id);
    }
  }
  if (failed.length) return false;
  console.log(`\n${TAG} ✓ 全部就绪。收工：node scripts/labs.mjs --stop`);
  return true;
}

async function main() {
  const argv = process.argv.slice(2);
  const labs = labSpecs({ env: process.env, repoRoot: ROOT });

  if (hasFlag(argv, '--list')) return void listRecipes(labs);
  if (hasFlag(argv, '--stop')) process.exit(stopLabs());
  if (hasFlag(argv, '--migrate')) return void runMigration(argv);

  const ports = labs.map((l) => l.port);
  const openPorts = await probePorts(ports);
  const probes = { portOpen: (p) => Boolean(openPorts.get(p)), pathExists: (p) => fs.existsSync(p) };
  const rows = planAll(labs, probes);

  if (!hasFlag(argv, '--up')) return void (await printHealthAndRequire(labs, rows, argv));

  const { todo, unknown } = selectToStart(labs, rows, readOpt(argv, '--up'));
  if (unknown.length) {
    console.error(`${TAG} ✗ 不认识的靶场 id：${unknown.join(', ')}（用 --list 看可用 id）`);
    process.exit(1);
  }
  if (!todo.length) {
    console.log(`${TAG} 没有需要拉起的靶场（都在监听，或前置不齐 —— 用不带 --up 的体检看原因）`);
    return;
  }
  const ok = await startSelectedLabs(todo);
  if (!ok) process.exit(1);
}

if (process.argv.includes('--selftest')) {
  selftest(labSpecs({ env: process.env, repoRoot: ROOT }));
  process.exit(0);
}

if (isDirectRun(import.meta.url)) await main();
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
//   node scripts/labs.mjs --selftest      # 自证纯函数判据（不起进程）
// 覆盖：所有路径都可用环境变量替换（MARIADB_HOME / PHP_EXE / DVWA_DIR / VAMPI_VENV / VAMPI_SRC /
//       NODE22_EXE / JUICE_DIR / JAVA_EXE / MAVEN_CMD / HSQL_JAR / BENCHMARK_DIR），见 --list。
// ============================================================================
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
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
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
async function main() {
  const argv = process.argv.slice(2);
  const labs = labSpecs({ env: process.env, repoRoot: ROOT });

  if (hasFlag(argv, '--list')) return void listRecipes(labs);
  if (hasFlag(argv, '--stop')) process.exit(stopLabs());

  const ports = labs.map((l) => l.port);
  const openPorts = await probePorts(ports);
  const probes = { portOpen: (p) => Boolean(openPorts.get(p)), pathExists: (p) => fs.existsSync(p) };
  const rows = planAll(labs, probes);

  const upOnly = hasFlag(argv, '--up');
  if (!upOnly) {
    console.log(`${TAG} 靶场体检（只探测，不起进程）：`);
    console.log(renderRows(rows));
    const require = readOpt(argv, '--require');
    if (require) {
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
    return;
  }

  const { todo, unknown } = selectToStart(labs, rows, readOpt(argv, '--up'));
  if (unknown.length) {
    console.error(`${TAG} ✗ 不认识的靶场 id：${unknown.join(', ')}（用 --list 看可用 id）`);
    process.exit(1);
  }
  if (!todo.length) {
    console.log(`${TAG} 没有需要拉起的靶场（都在监听，或前置不齐 —— 用不带 --up 的体检看原因）`);
    return;
  }
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
  if (failed.length) process.exit(1);
  console.log(`\n${TAG} ✓ 全部就绪。收工：node scripts/labs.mjs --stop`);
}

if (process.argv.includes('--selftest')) {
  selftest(labSpecs({ env: process.env, repoRoot: ROOT }));
  process.exit(0);
}

if (isDirectRun(import.meta.url)) await main();
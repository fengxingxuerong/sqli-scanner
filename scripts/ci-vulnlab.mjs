#!/usr/bin/env node
// ============================================================================
// scripts/ci-vulnlab.mjs —— [D272 2026-11-08] CI 侧拉起 VulnLab（外部裁判 5 号）
//
// 为什么需要它：acceptance 的 `vulnlab` 套件在 CI 长期 SKIP。D162 记录的实测教训是
// 「CI 上靶场对任何输入无差分响应（SQLite 种子未生效）」⇒ 自证探针失败 ⇒ 静默 SKIP。
// 本脚本走 D270（ci-dvwa.mjs）同构路径：pin 上游 commit 从 codeload 下载 → 备好 data/
// 目录（首次访问由靶场 config.php 自动建库灌种子）→ 起 php -S → 就绪探测 +
// 官方真值最低形态探针双重确认（探针才是「种子真生效」的判据）。
// e2e/vulnlab-lab/run.mjs 会复用这个端口，
// 不再自己 clone / spawn，从根上消掉「起得来但探针失败」的静默 SKIP。
//
// 用法：node scripts/ci-vulnlab.mjs up|stop|check
// 环境变量：VULNLAB_DIR / VULNLAB_PORT / VULNLAB_REF / PHP_BIN / VULNLAB_SKIP_DOWNLOAD
// 退出码：0 = 就绪；1 = 任一前置或步骤失败（显式报原因，绝不静默 SKIP）。
// ============================================================================
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const REPO = 'hediwen831-star/vulnlab';
/** 上游 pin：2026-10-25 的 main（与本机 .verify-labs/vulnlab 缓存同源，manifest 91 例）。 */
const REF = process.env.VULNLAB_REF || '34d3abb1b6b4e5c52f0f3288ec1a9727e000c363';
const DIR = path.resolve(ROOT, process.env.VULNLAB_DIR || path.join('.verify-labs', 'vulnlab-ci'));
const PORT = Number(process.env.VULNLAB_PORT) || 8135;
const PHP = process.env.PHP_BIN || 'php';
const PID_FILE = path.join(ROOT, '.box-agent-scratch', 'ci-vulnlab.pid');
const LOG_FILE = path.join(ROOT, '.box-agent-scratch', 'ci-vulnlab.log');
const BASE = `http://127.0.0.1:${PORT}`;

const log = (msg) => console.log(`[ci-vulnlab] ${msg}`);

/** 跑命令并返回 stdout；失败时保留原始错误链（lint: preserve-caught-error）。 */
function run(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw new Error(`命令失败：${cmd} ${args.join(' ')} —— ${String(e.stderr || e.message).slice(0, 600)}`, { cause: e });
  }
}

/**
 * PHP 启动参数：共享 php.ini 可能被 DVWA 场景锁死为 MySQL 形态（未启用 pdo_sqlite），
 * 故按 e2e/vulnlab-lab/run.mjs 同款做法 `-n` 裸启 + 按需补 pdo_sqlite，不改共享 ini。
 * Windows 本机从 PHP_BIN 目录推导 ext/；Linux 交给 PHP 自己的 extension_dir 找 .so。
 */
function phpBaseArgs() {
  // Linux runner 走正常 php.ini（pdo_sqlite 已在扩展列表里，ci.yml 另有 apt 兜底）；
  // 只有 Windows 本机的共享 php.ini 被 DVWA 场景锁死为 MySQL 形态，才需要裸启补 dll。
  if (process.platform !== 'win32') return [];
  const args = ['-n'];
  const mods = run(PHP, ['-n', '-m']);
  if (/^pdo_sqlite$/m.test(mods)) return args;
  const extDir = path.join(path.dirname(PHP), 'ext');
  if (fs.existsSync(path.join(extDir, 'php_pdo_sqlite.dll'))) {
    args.push('-d', `extension_dir=${extDir}`, '-d', 'extension=pdo_sqlite');
  } else {
    args.push('-d', 'extension=pdo_sqlite');
  }
  return args;
}

/** 前置：php 可执行 + pdo_sqlite 可用（用与真正起服务完全相同的参数检查）。 */
function preflight() {
  const v = run(PHP, ['-v']).split('\n').map((l) => l.trim()).find((l) => l.startsWith('PHP')) || '版本未知';
  log(`PHP：${v}`);
  const args = phpBaseArgs();
  const mods = run(PHP, [...args, '-m']);
  if (!/^pdo_sqlite$/m.test(mods)) {
    throw new Error(`PHP 缺 pdo_sqlite 扩展（${PHP} ${args.join(' ')} -m 里没有）—— Linux 需 apt 装 php<ver>-sqlite3`);
  }
}

/** 确保 pin 源码 + 种子库在 DIR；缺则按 pin 下载（幂等）。 */
async function ensureSource() {
  const lowPhp = path.join(DIR, 'html', 'sqli', 'low.php');
  if (fs.existsSync(lowPhp)) {
    log(`源码已就绪：${DIR}`);
  } else {
    if (process.env.VULNLAB_SKIP_DOWNLOAD === '1') throw new Error(`源码缺失且 VULNLAB_SKIP_DOWNLOAD=1：${DIR}`);
    const parent = path.dirname(DIR);
    fs.mkdirSync(parent, { recursive: true });
    const tgz = path.join(parent, `vulnlab-${REF.slice(0, 8)}.tar.gz`);
    log(`下载 pin 版本 ${REF.slice(0, 8)} …`);
    let buf;
    try {
      const r = await fetch(`https://codeload.github.com/${REPO}/tar.gz/${REF}`, { signal: AbortSignal.timeout(120000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      buf = Buffer.from(await r.arrayBuffer());
    } catch (e) {
      throw new Error(`下载 VulnLab 失败：${e.message}`, { cause: e });
    }
    fs.writeFileSync(tgz, buf);
    // Windows 的 tar 会把带盘符的绝对路径误判成远程主机（Cannot connect to <drive>:），
    // 故一律传相对 ROOT 的 POSIX 路径；Linux runner 上同样成立。
    const rel = (f) => path.relative(ROOT, f).replace(/\\/g, '/');
    run('tar', ['-xzf', rel(tgz), '-C', rel(parent)]);
    const extracted = fs.readdirSync(parent).find((n) => n.startsWith('vulnlab-') && fs.statSync(path.join(parent, n)).isDirectory());
    if (!extracted) throw new Error(`解压后找不到 vulnlab-* 目录（${parent}）`);
    fs.renameSync(path.join(parent, extracted), DIR);
    fs.rmSync(tgz, { force: true });
    log(`源码就绪：${DIR}`);
  }
  // 上游 tarball 不带 data/（config.php 首次访问 mkdir + 建表灌种子），这里只保证目录可写；
  // 「种子真生效」由起服务后的 selfTruthProbe 判定，绝不拿文件存在当证据。
  const dataDir = path.join(DIR, 'html', 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  log(`数据目录就绪：${dataDir}（种子由首次访问自动灌入，真值探针随后验证）`);
}

/** 起 php -S（detached + unref，父进程退出后仍在本 job 内存活）；pid 落文件供 stop 精确收工。 */
function startServer() {
  fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
  const fd = fs.openSync(LOG_FILE, 'a');
  const child = spawn(PHP, [...phpBaseArgs(), '-S', `127.0.0.1:${PORT}`, '-t', path.join(DIR, 'html')], {
    cwd: DIR, detached: true, windowsHide: true, stdio: ['ignore', fd, fd],
  });
  child.unref();
  fs.writeFileSync(PID_FILE, String(child.pid));
  log(`php -S 127.0.0.1:${PORT} 已启动（pid=${child.pid}）`);
}

/** GET 一个页面，返回 {status, text}；网络异常收敛成 status=0，由调用方判红。 */
async function http(url) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
    return { status: r.status, text: await r.text() };
  } catch (e) {
    return { status: 0, text: String(e.message) };
  }
}

/** 等 low.php 就绪（200 + 页面含 SQL 回显）。 */
async function waitUp(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    const r = await http(`${BASE}/sqli/low.php?id=1`);
    if (r.status === 200 && /VulnLab|SELECT/i.test(r.text)) { log('server 就绪（low.php 200 + SQL 回显）'); return; }
    last = `HTTP ${r.status}`;
    await new Promise((s) => setTimeout(s, 1000));
  }
  throw new Error(`php server ${timeoutMs}ms 内未就绪（${last}）—— 见 ${LOG_FILE}`);
}

/** 真值探针：low.php 对 `1 OR 1=1` 必须与基线有差分（与 run.mjs D162 同口径）。 */
async function selfTruthProbe() {
  const a = await http(`${BASE}/sqli/low.php?id=1`);
  const b = await http(`${BASE}/sqli/low.php?id=${encodeURIComponent('1 OR 1=1')}`);
  const diffPct = a.text.length > 0 ? Math.abs(b.text.length - a.text.length) / a.text.length : 1;
  if (!(a.status === 200 && b.status === 200 && diffPct > 0.03)) {
    throw new Error(`真值探针失败：基线 ${a.text.length}B / 探针 ${b.text.length}B（差 ${(diffPct * 100).toFixed(1)}%）—— 种子库或 pdo_sqlite 未生效，禁止静默 SKIP`);
  }
  log(`真值探针通过：${a.text.length}B → ${b.text.length}B（差 ${(diffPct * 100).toFixed(1)}%）`);
}

/** 按 pid 文件收工（只杀本脚本起的那一个，跨平台 SIGTERM）。 */
function stopServer() {
  if (!fs.existsSync(PID_FILE)) { log('无 pid 文件，跳过'); return; }
  const pid = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
  fs.rmSync(PID_FILE, { force: true });
  if (!Number.isInteger(pid) || pid <= 0) { log(`pid 文件非法（${pid}），跳过`); return; }
  try { process.kill(pid, 'SIGTERM'); log(`已收工 pid=${pid}`); }
  catch (e) { log(`pid=${pid} 已不在（${String(e.message).slice(0, 80)}）`); }
}

/** 入口：up / stop / check。 */
async function main() {
  const mode = process.argv[2] || 'up';
  if (mode === 'stop') { stopServer(); return; }
  if (!['up', 'check'].includes(mode)) throw new Error(`未知子命令：${mode}（up|stop|check）`);
  preflight();
  await ensureSource();
  if (mode === 'check') { log('前置检查通过（未拉进程）'); return; }
  startServer();
  await waitUp();
  await selfTruthProbe();
  log('VulnLab 已就绪，可跑 acceptance 的 vulnlab 套件（run.mjs 会复用端口）');
}

main().catch((e) => {
  console.error(`[ci-vulnlab] ✖ ${e.message}`);
  process.exit(1);
});

#!/usr/bin/env node
// ============================================================================
// scripts/ci-dvwa.mjs —— [D270 2026-11-07] CI 侧拉起 DVWA 外部裁判（Linux runner 与 Windows 本机同构）
//
// 为什么需要它：acceptance 的 `dvwa` 与「数据泄露实证（extract-proof）」两个套件在 CI 长期
// SKIP（`ci.yml` 原注释：「dvwa / benchmark 的 CI 化遗留：镜像内含 MySQL 启动链 / Java 构建链
// 未验证，不盲猜」）。本脚本只做 DVWA 的**源码 + PHP 内置服务器**路径（不用 docker 镜像），
// 因为这条路在本机已被 `scripts/lib/labs.mjs` 的 dvwaSpec 验证过，且 Ubuntu 24.04 runner
// 预装 PHP 8.3.6（`actions/runner-images` 的 Ubuntu2404-Readme：PHP 8.3.6）。
//
// 关键事实（别改成「自己写 config」）：
//   · DVWA 的 `config/config.inc.php.dist` 全量走 `getenv()`（`$DBMS = getenv('DBMS') ?: 'MySQL'`），
//     所以**不需要改写配置文件** —— 只在起 PHP 时传 DB_SERVER / DB_* / DISABLE_AUTHENTICATION 即可。
//     本机 `config.inc.php` 与 dist 逐行相同，是同一份 getenv 方案。
//   · setup.php 首次建表需要 CSRF token：`<input type='hidden' name='user_token' value='...' />`
//     （**单引号属性**，按双引号 grep 会抠不到 —— e2e/dvwa-lab/README.md 的坑）。
//
// 用法：
//   node scripts/ci-dvwa.mjs up      # 下载(可选) → 建库 → 起 php -S → setup → 就绪探测
//   node scripts/ci-dvwa.mjs stop    # 按 pid 文件收工（Windows 用 taskkill /T）
//   node scripts/ci-dvwa.mjs check   # 只跑前置检查（php/mysqli/源码），不拉进程
//
// 环境变量：DVWA_DIR / DVWA_PORT / DVWA_REF / PHP_BIN / MYSQL_HOST / MYSQL_PORT /
//           MYSQL_USER / MYSQL_PASSWORD / DVWA_SKIP_DOWNLOAD=1
// 退出码：0 = 就绪；1 = 任一前置或步骤失败（显式报原因，绝不静默 SKIP）。
// ============================================================================
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const require = createRequire(import.meta.url);

/** DVWA 上游 pin（2026-10-18 的 master；换版本必须同时改这里与 README 的说明） */
const DVWA_REF = process.env.DVWA_REF || 'a1978a2fed195acd093010af6395f86a281537ca';
const DIR = path.resolve(ROOT, process.env.DVWA_DIR || path.join('.verify-labs', 'DVWA-master'));
const PORT = Number(process.env.DVWA_PORT) || 8099;
const PHP = process.env.PHP_BIN || (process.platform === 'win32' ? 'D:/tools/php83/php.exe' : 'php');
const MYSQL = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || 'root',
};
const PID_FILE = path.join(ROOT, '.box-agent-scratch', 'ci-dvwa.pid');
const LOG_FILE = path.join(ROOT, '.box-agent-scratch', 'ci-dvwa.log');

const log = (msg) => console.log(`[ci-dvwa] ${msg}`);

/**
 * 跑一个命令并把 stdout/err 一起返回；失败时带原始错误链抛出（lint 的 preserve-caught-error）。
 * @param {string} cmd 可执行文件
 * @param {string[]} args 参数
 * @param {object} [opts] spawnSync 选项
 * @returns {string} stdout
 */
function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
  } catch (e) {
    throw new Error(`命令失败：${cmd} ${args.join(' ')} —— ${String(e.stderr || e.message).slice(0, 600)}`, { cause: e });
  }
}

/** 前置检查：php 可执行 + mysqli 扩展 + 源码目录可服务（index.php/login.php 存在）。 */
function preflight() {
  const v = run(PHP, ['-v']).split('\n').map((l) => l.trim()).find((l) => l.startsWith('PHP')) || '版本未知';
  log(`PHP：${v}`);
  const mods = run(PHP, ['-m']);
  if (!/^mysqli$/m.test(mods)) throw new Error(`PHP 缺 mysqli 扩展（${PHP} -m 里没有）—— Linux 需 apt-get install php8.3-mysql`);
  if (!/^pdo_mysql$/m.test(mods)) log('提示：缺 pdo_mysql（DVWA 默认走 mysqli，不阻塞）');
}

/**
 * 确保源码在 `DIR`：缺失则按 pin 的 commit 下载 tarball 并解压（幂等）。
 * `DVWA_SKIP_DOWNLOAD=1` 时只检查不下载（本机已有源码时用）。
 */
async function ensureSource() {
  if (fs.existsSync(path.join(DIR, 'index.php')) && fs.existsSync(path.join(DIR, 'login.php'))) {
    log(`源码已就绪：${DIR}`);
    return;
  }
  if (process.env.DVWA_SKIP_DOWNLOAD === '1') throw new Error(`源码缺失且 DVWA_SKIP_DOWNLOAD=1：${DIR}`);
  const parent = path.dirname(DIR);
  fs.mkdirSync(parent, { recursive: true });
  const tgz = path.join(parent, `DVWA-${DVWA_REF.slice(0, 8)}.tar.gz`);
  log(`下载 pin 版本 ${DVWA_REF.slice(0, 8)} …`);
  let buf;
  try {
    const r = await fetch(`https://codeload.github.com/digininja/DVWA/tar.gz/${DVWA_REF}`, { signal: AbortSignal.timeout(120000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    buf = Buffer.from(await r.arrayBuffer());
  } catch (e) {
    throw new Error(`下载 DVWA 失败：${e.message}`, { cause: e });
  }
  fs.writeFileSync(tgz, buf);
  run('tar', ['-xzf', tgz, '-C', parent]);
  const extracted = fs.readdirSync(parent).find((n) => n.startsWith('DVWA-') && fs.statSync(path.join(parent, n)).isDirectory());
  if (!extracted) throw new Error(`解压后找不到 DVWA-* 目录（${parent}）`);
  fs.renameSync(path.join(parent, extracted), DIR);
  fs.rmSync(tgz, { force: true });
  log(`源码就绪：${DIR}`);
}

/** 复制 `.dist` 为 `config.inc.php`（若缺）；内容不变 —— 全部走 getenv。 */
function ensureConfig() {
  const dst = path.join(DIR, 'config', 'config.inc.php');
  if (fs.existsSync(dst)) { log('config.inc.php 已存在（getenv 方案，无需改写）'); return; }
  fs.copyFileSync(path.join(DIR, 'config', 'config.inc.php.dist'), dst);
  log('config.inc.php 由 .dist 复制（getenv 驱动）');
}

/** 建库（DVWA setup.php 会自己建表，但库必须先存在）。 */
async function createDatabase() {
  const mysql = require(path.join(ROOT, 'server', 'node_modules', 'mysql2', 'promise'));
  const conn = await mysql.createConnection(MYSQL);
  try {
    await conn.query('CREATE DATABASE IF NOT EXISTS dvwa');
    log(`库 dvwa 就绪（${MYSQL.host}:${MYSQL.port}）`);
  } finally {
    await conn.end();
  }
}

/** 起 PHP 内置服务器（detached + unref，父进程退出后仍在本 job 内存活）。 */
function startServer() {
  fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
  const fd = fs.openSync(LOG_FILE, 'a');
  const child = spawn(PHP, ['-S', `127.0.0.1:${PORT}`, '-t', DIR], {
    cwd: DIR,
    detached: true,
    stdio: ['ignore', fd, fd],
    env: {
      ...process.env,
      DBMS: 'MySQL',
      DB_SERVER: MYSQL.host,
      DB_PORT: String(MYSQL.port),
      DB_DATABASE: 'dvwa',
      DB_USER: MYSQL.user,
      DB_PASSWORD: MYSQL.password,
      DISABLE_AUTHENTICATION: 'true',
      DEFAULT_SECURITY_LEVEL: 'low',
    },
  });
  child.unref();
  fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
  fs.writeFileSync(PID_FILE, String(child.pid));
  log(`php -S 127.0.0.1:${PORT} 已启动（pid=${child.pid}）`);
}

/**
 * 发一个 HTTP 请求并把 cookie 串起来（setup 需要同一会话的 PHPSESSID）。
 * @param {string} url 地址
 * @param {{method?:string, body?:string, cookie?:string}} [opt] 请求选项
 * @returns {Promise<{status:number, text:string, setCookie:string[]}>} 响应
 */
async function http(url, opt = {}) {
  const headers = { 'User-Agent': 'ci-dvwa' };
  if (opt.cookie) headers.Cookie = opt.cookie;
  if (opt.body) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const r = await fetch(url, { method: opt.method || 'GET', headers, body: opt.body, signal: AbortSignal.timeout(30000) });
  const setCookie = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : [];
  return { status: r.status, text: await r.text(), setCookie };
}

/** 等 PHP server 起来（首页可达）。 */
async function waitUp(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const r = await http(`http://127.0.0.1:${PORT}/login.php`);
      if (r.status === 200) { log('server 就绪（login.php 200）'); return; }
      last = `HTTP ${r.status}`;
    } catch (e) { last = String(e.message).slice(0, 80); }
    await new Promise((s) => setTimeout(s, 1000));
  }
  throw new Error(`php server ${timeoutMs}ms 内未就绪（${last}）—— 见 ${LOG_FILE}`);
}

/** 跑 setup.php：GET 抠 user_token（单引号属性）→ POST create_db。 */
async function runSetup() {
  const base = `http://127.0.0.1:${PORT}`;
  const first = await http(`${base}/setup.php`);
  const cookie = first.setCookie.map((c) => c.split(';')[0]).join('; ');
  const token = /name=['"]user_token['"]\s+value=['"]([^'"]+)['"]/.exec(first.text)?.[1];
  if (!token) throw new Error('setup.php 未拿到 user_token（页面结构变了？）');
  const post = await http(`${base}/setup.php`, {
    method: 'POST', cookie, body: `create_db=Create+%2F+Reset+Database&user_token=${encodeURIComponent(token)}`,
  });
  const ok = /Database has been created|Database has been reset|Setup successful/i.test(post.text);
  if (!ok) throw new Error(`setup 未成功（HTTP ${post.status}）：${post.text.replace(/\s+/g, ' ').slice(0, 300)}`);
  log('setup 完成（库表已建）');
}

/** 就绪探测：sqli low 页面必须 200 且回显 admin（与 e2e/dvwa-lab/run.mjs 的真值口径一致）。 */
async function waitReady(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  const url = `http://127.0.0.1:${PORT}/vulnerabilities/sqli/?id=1&Submit=Submit`;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const r = await http(url, { cookie: 'security=low; PHPSESSID=dvwa-lab-session' });
      if (r.status === 200 && r.text.includes('admin')) { log('DVWA 就绪（sqli low 200 + admin）'); return; }
      last = `HTTP ${r.status} admin=${r.text.includes('admin')}`;
    } catch (e) { last = String(e.message).slice(0, 80); }
    await new Promise((s) => setTimeout(s, 1000));
  }
  throw new Error(`DVWA ${timeoutMs}ms 内未就绪（${last}）`);
}

/** 按 pid 文件收工（只杀本脚本起的那一个）。 */
function stopServer() {
  if (!fs.existsSync(PID_FILE)) { log('无 pid 文件，跳过'); return; }
  const pid = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
  fs.rmSync(PID_FILE, { force: true });
  if (!Number.isInteger(pid) || pid <= 0) { log(`pid 文件非法（${pid}），跳过`); return; }
  try {
    if (process.platform === 'win32') execFileSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' });
    else process.kill(pid, 'SIGTERM');
    log(`已收工 pid=${pid}`);
  } catch (e) {
    log(`pid=${pid} 已不在（${String(e.message).slice(0, 80)}）`);
  }
}

/** 入口：up / stop / check。 */
async function main() {
  const mode = process.argv[2] || 'up';
  if (mode === 'stop') { stopServer(); return; }
  if (!['up', 'check'].includes(mode)) throw new Error(`未知子命令：${mode}（up|stop|check）`);
  preflight();
  await ensureSource();
  ensureConfig();
  if (mode === 'check') { log('前置检查通过（未拉进程）'); return; }
  await createDatabase();
  startServer();
  await waitUp();
  await runSetup();
  await waitReady();
  log('DVWA 已就绪，可跑 acceptance 的 dvwa / extract-proof 套件');
}

main().catch((e) => {
  console.error(`[ci-dvwa] ✖ ${e.message}`);
  process.exit(1);
});

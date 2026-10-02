// ============================================================================
// e2e/login-lab/run.mjs —— 登录编排（--login-url）的真机验收
//
// 回答两个问题：
//   A. **会话会过期的目标，能不能扫完**？—— 认证此前只有「静态注入 cookie」+ 会话失效
//      **检测**（scanValidityGuard 判 authLost 后建议人工重取 cookie）。token 一小时过期
//      的目标扫到一半全变 401 ⇒ 后半程全判「不可注入」。本模块补的是自动重登 + 重试。
//   B. **A 的检出是不是白送的**？—— 必须有对照组：不给 --login-url 时应 **0 检出**。
//      没有这条反例，靶站若根本不校验会话，A 会"天然绿"，整套件等于没验任何东西。
//
// 真实性取舍（先说清楚边界）：
//   · 目标用**真 SQL 引擎**（sql.js / SQLite WASM）+ 真 HTTP 靶站 + 真 CLI 进程（spawn）；
//     登录是真表单（密码框 + hidden csrf + urlencoded 提交 + Set-Cookie），不是 mock。
//   · 本套件验的是**登录编排**（自动重登 / 会话维持 / 检出链路不被 401 打断），
//     不是检出能力 —— 检出能力由 real-mysql-lab / api-range-lab 那两套真 MySQL 套件背书。
//   · 单独的 SQLite 检出数字不作为对外口径（方言与真 MySQL 不同源）。
// ============================================================================
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');

const USER = 'admin';
const PASS = 's3cret';
const CSRF = 't0k-login-lab';
/** 每个会话只用这么多次就过期 —— 强制「自动重登」路径真的被走到 */
const SESSION_MAX_USES = 6;

const fails = [];
const check = (cond, msg) => { if (!cond) fails.push(msg); };
const note = (s) => console.log(`   ${s}`);

async function startTarget() {
  const { loadSqlJs } = await import(pathToFileURL(path.join(ROOT, 'server', 'src', 'core', 'sqlJsLoader.js')).href);
  const initSqlJs = await loadSqlJs();
  const SQL = await (typeof initSqlJs === 'function' ? initSqlJs({}) : initSqlJs);
  const db = new SQL.Database();
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)');
  db.run("INSERT INTO users VALUES (1,'admin','admin@lab.local'),(2,'alice','alice@lab.local')");

  const run = (sql) => {
    try {
      const res = db.exec(sql);
      if (!res.length) return [];
      const cols = res[0].columns;
      return res[0].values.map((row) => Object.fromEntries(cols.map((c, i) => [c, row[i]])));
    } catch {
      return null;
    }
  };

  // 会话表：sid → 已用次数（超过上限即失效）
  const sessions = new Map();
  const stats = { loginPosts: 0, loginOk: 0, protected401: 0, protected200: 0 };
  let sidSeq = 0;

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const cookies = Object.fromEntries(
      String(req.headers.cookie || '').split(';').filter(Boolean).map((c) => {
        const i = c.indexOf('=');
        return [c.slice(0, i).trim(), c.slice(i + 1)];
      }),
    );

    // —— 登录页（标准表单：hidden csrf + 文本用户框 + 密码框）——
    if (u.pathname === '/login' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(
        '<html><body><form method="post" action="/login">'
        + `<input type="hidden" name="csrf" value="${CSRF}">`
        + '<input type="text" name="username">'
        + '<input type="password" name="password">'
        + '<button>登录</button></form></body></html>',
      );
      return;
    }
    // —— 登录提交 ——
    if (u.pathname === '/login' && req.method === 'POST') {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        stats.loginPosts += 1;
        const sp = new URLSearchParams(raw);
        const ok = sp.get('username') === USER && sp.get('password') === PASS && sp.get('csrf') === CSRF;
        if (!ok) {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          res.end('<html><body><form><input type="password" name="password"></form></body></html>');
          return;
        }
        stats.loginOk += 1;
        sidSeq += 1;
        const sid = `sid-${sidSeq}`;
        sessions.set(sid, 0);
        res.writeHead(302, { 'set-cookie': `sid=${sid}; Path=/`, location: '/home' });
        res.end();
      });
      return;
    }
    if (u.pathname === '/home') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<html><body>welcome</body></html>');
      return;
    }
    // —— 受保护的可注入端点（无有效会话 ⇒ 401）——
    if (u.pathname === '/num') {
      const sid = cookies.sid;
      if (!sid || !sessions.has(sid)) {
        stats.protected401 += 1;
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' }).end('<html><body>unauthorized</body></html>');
        return;
      }
      const uses = sessions.get(sid) + 1;
      if (uses > SESSION_MAX_USES) {
        sessions.delete(sid); // ★ 会话过期：逼出「自动重登」路径
        stats.protected401 += 1;
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' }).end('<html><body>session expired</body></html>');
        return;
      }
      sessions.set(sid, uses);
      stats.protected200 += 1;
      const rows = run(`SELECT id, username, email FROM users WHERE id = ${u.searchParams.get('id') ?? '1'}`);
      const body = rows === null
        ? '<div class="card">error</div>'
        : `<table>${rows.map((r) => `<tr><td>${r.id}</td><td>${r.username}</td><td>${r.email}</td></tr>`).join('')}</table>`;
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(`<html><body>${body}</body></html>`);
      return;
    }
    res.writeHead(404).end('not found');
  });

  const port = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
  return { port, stats, stop: () => new Promise((r) => server.close(r)) };
}

async function runCli(args) {
  const p = spawn(process.execPath, [path.join(ROOT, 'server', 'bin', 'cli.js'), ...args], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  p.stdout.on('data', (d) => (stdout += d));
  p.stderr.on('data', (d) => (d ? (stderr += d) : null));
  const code = await new Promise((resolve) => p.once('exit', resolve));
  return { code, stdout, stderr };
}

const target = await startTarget();
const base = `http://127.0.0.1:${target.port}`;
const outDir = path.join(ROOT, 'logs', 'login-lab-out');
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const COMMON = [
  '--level', '1', '--risk', '1', '--technique', 'union,error,boolean',
  '--rate', '0', '--req-rate', '0', '--timeout', '60000', '--format', 'json',
];

// ============================================================================
// 场景 B（**先跑对照组**）：不给 --login-url ⇒ 必须 0 检出
//   没有这条，A 的"检出成功"无法证明是登录编排的功劳 —— 靶站若不校验会话，A 天然绿。
// ============================================================================
let control = { vulns: -1, code: -1 };
{
  // ⚠ 单目标模式的 --out 是**文件路径**（批量模式才是目录）—— 写错会 ENOTDIR 崩掉整个套件
  const o = path.join(outDir, 'B-control.json');
  const r = await runCli(['-u', `${base}/num?id=1`, '--out', o, ...COMMON]);
  if (fs.existsSync(o)) {
    const rep = JSON.parse(fs.readFileSync(o, 'utf8'));
    control = { vulns: (rep.vulns || []).length, code: r.code };
  } else {
    control = { vulns: -1, code: r.code };
  }
  check(
    control.vulns === 0,
    `B: 不给 --login-url 时应当一个都检不出（靶站挡在 401 之外），实得 ${control.vulns} 条`
    + ` —— 若非 0，说明靶站没真校验会话，A 场景的绿就是白送的`,
  );
  note(`B 对照组：退出码 ${r.code}，检出 ${control.vulns} 条（期望 0）`);
}

// ============================================================================
// 场景 A：--login-url + --auth ⇒ 会话反复过期也要扫完并检出
// ============================================================================
let main = { vulns: -1, code: -1, points: -1, verdict: '' };
{
  const o = path.join(outDir, 'A-login.json');
  const before = { ...target.stats };
  const r = await runCli([
    '-u', `${base}/num?id=1`,
    '--login-url', `${base}/login`,
    '--auth', `${USER}:${PASS}`,
    '--out', o, ...COMMON,
  ]);
  check(fs.existsSync(o), `A: 应有报告落盘（${o}）；stderr 尾部：${r.stderr.slice(-500)}`);
  if (fs.existsSync(o)) {
    const rep = JSON.parse(fs.readFileSync(o, 'utf8'));
    main = {
      vulns: (rep.vulns || []).length,
      code: r.code,
      points: (rep.points || []).length,
      verdict: String(rep?.summary?.verdict || ''),
    };
  }
  check(r.code === 0 || r.code === 2, `A: 应正常退出（0 或 2），实得 ${r.code}；stderr 尾部：${r.stderr.slice(-500)}`);
  check(main.points > 0, `A: 登录后应发现可注入点，实得 ${main.points}`);
  check(main.vulns > 0, `A: 登录后应真检出注入，实得 ${main.vulns} 条 —— 登录编排没把会话维持住？`);

  const loginPosts = target.stats.loginPosts - before.loginPosts;
  const loginOk = target.stats.loginOk - before.loginOk;
  // ★ 核心语义：会话是「用 N 次就过期」的，一次扫描必然要重登多次。
  //   只登录 1 次 ⇒ 说明自动重登根本没发生（或根本没被触发）。
  check(loginOk >= 2, `A: 会话反复过期 ⇒ 应发生多次自动重登，实得 ${loginOk} 次成功登录`);
  check(loginPosts === loginOk, `A: 登录提交都应当成功（凭据是对的），提交 ${loginPosts} / 成功 ${loginOk}`);
  check(
    target.stats.protected401 > 0,
    'A: 靶站应真的发过 401（否则「自动重登」这条路径根本没被走到，套件在空转）',
  );
  note(`A 登录编排：退出码 ${r.code}，points=${main.points} vulns=${main.vulns}；登录 ${loginOk}/${loginPosts} 次成功`);
  note(`   靶站计数：受保护端点 200=${target.stats.protected200} / 401=${target.stats.protected401}`);
}

await target.stop();

if (fails.length) {
  console.error(`[FAIL] 登录编排靶场：\n  - ${fails.join('\n  - ')}`);
  process.exit(1);
}
console.log(`[PASS] 登录编排：A（--login-url）会话反复过期仍扫完并检出 ${main.vulns} 条；B（不给登录）0 检出 —— 反例成立`);
console.log('   检出数仅记录，不作对外口径（SQLite 与真 MySQL 不同源）');
process.exit(0);

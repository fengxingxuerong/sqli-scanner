// ============================================================================
// e2e/csrf-lab/e2e.mjs —— CSRF 防护目标端到端验证（--csrf-url 真实闭环）
// ============================================================================
// 场景（渗透 100% 常见）：目标所有业务接口校验 anti-CSRF token，无 token/错 token
// 一律 403/302。此前引擎对该类目标完全无能为力（token 永远缺失 → 全部误判无注入）。
// 闭环断言：
//   ① 引擎配 csrfUrl 后自动取页提取 token 并携带
//   ② token 有效请求数 > 无效数（证明携带真实生效）
//   ③ /search 注入点被正常检出（union 通道）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const express = _require('express');
const mysql = _require('mysql2/promise');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);

const PORT = Number(process.env.CSRF_LAB_PORT) || 8281;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = 'sess_csrf_token_20260914';
let tokenOk = 0, tokenBad = 0;

const app = express();
app.use(express.urlencoded({ extended: true }));

// CSRF 取页：hidden token
app.get('/login', (req, res) => {
  res.send(`<form method="post" action="/login"><input type="hidden" name="csrf_token" value="${TOKEN}"><input name="user"><input name="pass"><button>go</button></form>`);
});
app.post('/login', (req, res) => {
  if (req.body.csrf_token === TOKEN) { tokenOk++; res.send('<p>welcome dashboard</p>'); }
  else { tokenBad++; res.redirect(302, '/login'); }
});

// 目标注入点：token 校验 + 真 MySQL LIKE 注入（sqli_lab.users）
const pool = mysql.createPool({ host: '127.0.0.1', port: 3306, user: 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: 'sqli_lab', connectionLimit: 4 });
app.get('/search', (req, res) => {
  if (req.query.csrf_token !== TOKEN) { tokenBad++; return res.status(403).send('<p>csrf invalid</p>'); }
  tokenOk++;
  const kw = String(req.query.kw ?? 'a');
  pool.query(`SELECT id, username, email FROM users WHERE username LIKE '%${kw}%'`)
    .then(([rows]) => {
      const rowsHtml = (rows || []).map((r) => `<tr><td>${r.id}</td><td>${r.username}</td><td>${r.email}</td></tr>`).join('');
      res.send(`<!DOCTYPE html><html><body><h1>Search</h1><table border="1"><tr><th>id</th><th>user</th><th>email</th></tr>${rowsHtml}</table></body></html>`);
    })
    .catch((err) => res.status(500).send('Query error: ' + err.message));
});

const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[csrf-lab] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[csrf-lab] 靶场就绪 ${BASE}/search?kw=a（token 校验强制）`);

// MySQL 可用性前置
try { await pool.query('SELECT 1'); } catch (e) {
  console.log(`[SKIP] MySQL 不可连（${e.message}）——环境缺项`);
  server.close(); await pool.end();
  process.exit(0);
}

// 引擎扫描：配 csrfUrl + token 名
const sm = new ScanManager();
const scanId = await sm.start({
  url: `${BASE}/search?kw=a`,
  config: {
    concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000,
    techniques: ['union', 'error', 'boolean'],
    csrfUrl: `${BASE}/login`, csrfTokenName: 'csrf_token', csrfRefreshFreq: 30,
  },
});
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 40));
}
const rep = sm.getReport(scanId) || {};
const techs = [...new Set((rep.vulns || []).map((v) => v.technique))];
console.log(`检出: ${JSON.stringify(techs)} | token 有效请求: ${tokenOk} | 无效: ${tokenBad}`);
const pass = techs.length > 0 && tokenOk > tokenBad;
console.log(`\n[${pass ? 'PASS' : 'FAIL'}] CSRF 防护目标扫描闭环（取页 → 携带 → 检出）`);

server.close();
await pool.end();
process.exit(pass ? 0 : 1);

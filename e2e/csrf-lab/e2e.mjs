// ============================================================================
// e2e/csrf-lab/e2e.mjs —— CSRF 防护目标端到端验证（--csrf-url 真实闭环）
// ============================================================================
// 场景（渗透 100% 常见）：目标所有业务接口校验 anti-CSRF token，无 token/错 token
// 一律 403/302。此前引擎对该类目标完全无能为力（token 永远缺失 → 全部误判无注入）。
// 闭环断言：
//   ① 引擎配 csrfUrl 后自动取页提取 token 并携带
//   ② token 有效请求数 > 无效数（证明携带真实生效）
//   ③ /search 注入点被正常检出（union 通道）
//   ④ [D279] --null-connection + --csrf-url：HEAD 通道必须真的抵达靶站且带 token。
//     此前 withSafeUrl/withCsrf/withLoginFlow 三个会话包装把 headRequest 丢掉 ⇒
//     sendHead 静默回退 GET：扫描照样出结论，但 HEAD 通道整个失效且无告警（TODO §10）。
//     判据以靶站侧计数为准（不采信客户端自报）：修复前 headOk 恒为 0 ⇒ 本场景必红。
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
// [D279] 场景④ 专用：靶站侧 HEAD 计数（携带有效 token 的 HEAD / 未携带的 HEAD）
let headOk = 0, headBad = 0;

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
// [2026-09-18] 连接参数改读环境变量：默认仍是 127.0.0.1:3306/root（向后兼容），
// 但可指向隔离沙箱（e2e/run-with-sandbox.py 注入 MYSQL_HOST/PORT/USER/PASSWORD）。
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  connectionLimit: 4,
});
app.get('/search', (req, res) => {
  const isHead = req.method === 'HEAD'; // express 对 GET 路由自动处理 HEAD（--null-connection 的通道）
  if (req.query.csrf_token !== TOKEN) { tokenBad++; if (isHead) headBad++; return res.status(403).send('<p>csrf invalid</p>'); }
  tokenOk++; if (isHead) headOk++;
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

const waitScan = async (sm, scanId, timeoutMs = 120000) => {
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > timeoutMs) { sm.stop(scanId); break; }
    await new Promise((r) => setTimeout(r, 40));
  }
};

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
await waitScan(sm, scanId);
const rep = sm.getReport(scanId) || {};
const techs = [...new Set((rep.vulns || []).map((v) => v.technique))];
console.log(`检出: ${JSON.stringify(techs)} | token 有效请求: ${tokenOk} | 无效: ${tokenBad}`);
const pass = techs.length > 0 && tokenOk > tokenBad;
console.log(`\n[${pass ? 'PASS' : 'FAIL'}] CSRF 防护目标扫描闭环（取页 → 携带 → 检出）`);

// ── 场景④ [D279]：--null-connection + --csrf-url 同靶复扫 ────────────────────
// HEAD 通道断言（靶站侧计数为准）：
//   a) headOk >= 2：null-connection 的布尔快判相位至少发基线 HEAD×2 —— 修复前该数恒为 0
//      （sendHead 静默回退 GET），此断言即缺陷显形面；
//   b) headBad === 0：每一条 HEAD 都携带有效 token —— HEAD 过会话层加工，不是裸透传；
//   c) 检出结论不受影响：HEAD/GET 双通道同会话（sendHead P0-FIX 的口径），照样出结论。
headOk = 0; headBad = 0;
const scanId2 = await sm.start({
  url: `${BASE}/search?kw=a`,
  config: {
    concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000,
    techniques: ['union', 'error', 'boolean'],
    csrfUrl: `${BASE}/login`, csrfTokenName: 'csrf_token', csrfRefreshFreq: 30,
    nullConnection: true,
  },
});
await waitScan(sm, scanId2);
const rep2 = sm.getReport(scanId2) || {};
const techs2 = [...new Set((rep2.vulns || []).map((v) => v.technique))];
console.log(`场景④ 检出: ${JSON.stringify(techs2)} | HEAD 有效: ${headOk} | HEAD 无效: ${headBad}`);
const pass4 = techs2.length > 0 && headOk >= 2 && headBad === 0;
console.log(`[${pass4 ? 'PASS' : 'FAIL'}] --null-connection + --csrf-url：HEAD 通道抵达靶站且带 token（修复前 headOk 恒为 0）`);

server.close();
await pool.end();
process.exit(pass && pass4 ? 0 : 1);

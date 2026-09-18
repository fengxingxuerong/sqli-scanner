// ============================================================================
// e2e/crawl-lab/e2e.mjs —— --crawl / --forms 攻击面发现真机验证
// ============================================================================
// 场景（真实交付常态）：注入点不在入口 URL 上，要靠爬虫发现。
// 靶场三层：/ (入口无参数) → 链接 → /item?id=1（数值注入点）→ 链接 → /search 表单页
// 断言：
//   ① --crawl 1：入口页链接被爬到，/item 注入点自动发现并检出 union
//   ② --forms --crawl 2：/search 表单被发现（POST 注入点）且检出
//   ③ scope：爬虫不越域（靶场带一个外域链接，不产生该外域的点）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const mysql = _require('mysql2/promise');
const express = _require('express');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);

const PORT = Number(process.env.CRAWL_LAB_PORT) || 8287;
const BASE = `http://127.0.0.1:${PORT}`;

// [2026-09-18] 连接参数改读环境变量：默认仍是 127.0.0.1:3306/root（向后兼容），
// 但可指向隔离沙箱（e2e/run-with-sandbox.py 注入 MYSQL_HOST/PORT/USER/PASSWORD）。
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  connectionLimit: 6,
});
try { await pool.query('SELECT 1'); } catch (e) {
  console.log(`[SKIP] MySQL 不可连（${e.message.split('\n')[0]}）`);
  await pool.end(); process.exit(0);
}

const app = express();
app.get('/', (req, res) => {
  // 入口页：无注入参数，只有两条站内链接 + 一条外域链接（scope 试探）
  res.send(`<!DOCTYPE html><html><body><h1>Home</h1><a href="/item?id=1">item</a><a href="/search?pre=1">search</a><a href="http://external.example.com/never">external</a></body></html>`);
});
app.get('/item', async (req, res) => {
  const id = String(req.query.id ?? '1');
  try {
    const [rows] = await pool.query(`SELECT id, username FROM users WHERE id = ${id}`);
    res.send(`<!DOCTYPE html><html><body><h1>Item</h1><table border="1">${rows.map((r) => `<tr><td>${r.id}</td><td>${r.username}</td></tr>`).join('')}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message.split('\n')[0]); }
});
app.get('/search', (req, res) => {
  // 表单页：POST 搜索（数值注入）
  res.send(`<!DOCTYPE html><html><body><form method="post" action="/doSearch"><input name="uid" value="1"><button>go</button></form></body></html>`);
});
app.post('/doSearch', express.urlencoded({ extended: true }), async (req, res) => {
  const uid = String(req.body?.uid ?? '1');
  try {
    const [rows] = await pool.query(`SELECT id, username FROM users WHERE id = ${uid}`);
    res.send(`<!DOCTYPE html><html><body><h1>Result</h1><table border="1">${rows.map((r) => `<tr><td>${r.id}</td><td>${r.username}</td></tr>`).join('')}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message.split('\n')[0]); }
});
// 爬虫越域试探哨兵：外域请求会被 scope 拦，记录命中
let externalHit = false;
app.get('/never', (req, res) => { externalHit = true; res.send('should not be crawled'); });

const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[crawl-lab] 靶场端口监听失败: ' + e.message)));
});
console.log(`[crawl-lab] 靶场就绪 ${BASE}/`);

// ---- 断言 ①：--crawl 1 从入口发现 /item ----
const sm = new ScanManager();
const s1 = await sm.start({ url: `${BASE}/`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union'], crawlDepth: 1, level: 3 } });
const t0 = Date.now();
for (;;) { const s = sm.scans.get(s1); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t0 > 120000) break; await new Promise((r) => setTimeout(r, 40)); }
const r1 = sm.getReport(s1) || {};
const params = (r1.points || []).map((p) => `${p.param}@${(p.url || p.location || '')}`);
const itemFound = (r1.points || []).some((p) => p.param === 'id');
const union1 = (r1.vulns || []).some((v) => v.technique === 'union');
console.log(`[① crawl1] points=${JSON.stringify(params)} itemFound=${itemFound} union=${union1}`);

// ---- 断言 ③：外域未被爬（scope 纪律）----
console.log(`[③ scope] external.example.com 被请求: ${externalHit ? '是(FAIL)' : '否(PASS)'}`);

// ---- 断言 ②：--forms（POST 表单注入点）----
const s2 = await sm.start({ url: `${BASE}/search?pre=1`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union', 'error', 'boolean'], crawlForms: true, level: 3 } });
const t1 = Date.now();
for (;;) { const s = sm.scans.get(s2); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t1 > 120000) break; await new Promise((r) => setTimeout(r, 40)); }
const r2 = sm.getReport(s2) || {};
const formPoint = (r2.points || []).find((p) => p.param === 'uid');
const formHit = (r2.vulns || []).some((v) => v.technique === 'union' || v.technique === 'error' || v.technique === 'boolean');
console.log(`[② forms] 表单点 uid=${!!formPoint} 检出=${formHit}`);

const ok = itemFound && union1 && !externalHit && !!formPoint && formHit;
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] --crawl/--forms 攻击面发现真机闭环`);
server.close();
await pool.end();
process.exit(ok ? 0 : 1);

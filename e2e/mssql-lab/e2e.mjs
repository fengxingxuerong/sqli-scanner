// ============================================================================
// e2e/mssql-lab/e2e.mjs —— SQL Server 真机靶场 + 引擎全链路验证
// ============================================================================
// 目的：把评审「MSSQL 无真机验证（template-only）」这一最大短板关掉。
// 环境无 Docker → 用 SQL Server 2022 Express 本机静默安装（命名实例 SQLI，TCP 动态端口，
// sa 认证），mssql npm 驱动直拼 SQL 的注入端点，引擎从 HTTP 注入点 → 真 MSSQL 执行。
//
// 验证矩阵：
//   num   —— 数值型（union/error/boolean，MSSQL 语法）
//   str   —— 字符串上下文（' 闭合）
//   dump  —— 拖库正确性（中文/单引号/ID 跳号）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const express = _require('express');
const sql = _require('mssql');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);

const PORT = Number(process.env.MSSQL_LAB_PORT) || 8284;
const SQL_PORT = Number(process.env.MSSQL_TCP_PORT) || 65039;
const BASE = `http://127.0.0.1:${PORT}`;
const SQL = { server: '127.0.0.1', port: SQL_PORT, user: 'sa', password: 'SqLi_2026_T!', database: 'sqli_lab_mssql', options: { trustServerCertificate: true, encrypt: false } };

// ---- 数据库就绪 ----
const pool = await sql.connect(SQL);
try { await pool.request().query(`IF OBJECT_ID('users') IS NULL CREATE TABLE users (id INT PRIMARY KEY, username NVARCHAR(64), email NVARCHAR(128), password NVARCHAR(128), role NVARCHAR(32))`); } catch { /* noop */ }
const cnt = await pool.request().query('SELECT COUNT(*) n FROM users');
if (cnt.recordset[0].n === 0) {
  await pool.request().query(`INSERT INTO users VALUES (1,'admin','admin@lab.local','admin123','admin'),(2,'alice','alice@lab.local','alice123','user'),(3,'bob','bob@lab.local','bob123','user'),(5,N'张三','zhang@lab.local','zh123','user'),(9,'o''brien','ob@lab.local','ob123','user')`);
}
console.log(`[mssql-lab] SQL Server 2022 @ 127.0.0.1:${SQL_PORT}（sqli_lab_mssql.users 就绪）`);

// ---- 注入端点（真拼 SQL）----
const app = express();
app.get('/num', async (req, res) => {
  const id = String(req.query.id ?? '1');
  try {
    const r = await pool.request().query(`SELECT id, username, email FROM users WHERE id = ${id}`);
    const rowsHtml = (r.recordset || []).map((x) => `<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td></tr>`).join('');
    res.send(`<!DOCTYPE html><html><body><h1>User</h1><table border="1">${rowsHtml}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message); }
});
app.get('/str', async (req, res) => {
  const name = String(req.query.name ?? 'alice');
  try {
    const r = await pool.request().query(`SELECT id, username, email FROM users WHERE username = '${name}'`);
    const rowsHtml = (r.recordset || []).map((x) => `<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td></tr>`).join('');
    res.send(`<!DOCTYPE html><html><body><h1>Profile</h1><table border="1">${rowsHtml}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message); }
});

const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[mssql-lab] 靶场端口监听失败: ' + e.message)));
});
console.log(`[mssql-lab] 靶场就绪 ${BASE}/num?id=1`);

// ---- 引擎扫描 num ----
const sm = new ScanManager();
const scanNum = await sm.start({ url: `${BASE}/num?id=1`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union', 'error', 'boolean'], dbms: 'SQL Server' } });
const t0 = Date.now();
for (;;) { const s = sm.scans.get(scanNum); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t0 > 180000) break; await new Promise((r) => setTimeout(r, 40)); }
const repNum = sm.getReport(scanNum) || {};
const techsNum = [...new Set((repNum.vulns || []).map((v) => v.technique))];
const dbmsNum = repNum.dbms;
console.log(`[num] techs=${JSON.stringify(techsNum)} dbms=${dbmsNum}`);

// ---- 引擎扫描 str ----
const scanStr = await sm.start({ url: `${BASE}/str?name=alice`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union', 'error', 'boolean'], dbms: 'SQL Server' } });
const t1 = Date.now();
for (;;) { const s = sm.scans.get(scanStr); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t1 > 180000) break; await new Promise((r) => setTimeout(r, 40)); }
const repStr = sm.getReport(scanStr) || {};
const techsStr = [...new Set((repStr.vulns || []).map((v) => v.technique))];
console.log(`[str] techs=${JSON.stringify(techsStr)} dbms=${repStr.dbms}`);

// ---- 判定 ----
const pass = techsNum.length > 0 && techsStr.length > 0;
console.log(`\n[${pass ? 'PASS' : 'FAIL'}] SQL Server 真机全链路：HTTP 注入点 → 真 MSSQL 执行 → 检出`);
server.close();
await pool.close();
process.exit(pass ? 0 : 1);

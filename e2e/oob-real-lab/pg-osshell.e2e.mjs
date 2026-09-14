// ============================================================================
// pg-osshell.e2e.mjs —— PostgreSQL os-shell（COPY ... FROM PROGRAM）真机闭环验证
// ============================================================================
// 目的：关闭评审「后渗透断链」清单中的 os-shell 一项——pgOsShell 此前只有 mock 单测，
// 未在真实 PG 上跑通。本脚本复用 oob-real-lab 的真 PG 16.2 靶场：
//   1. initDb 建 oob_lab 库（postgres/postgres 超管）
//   2. 起靶场 /shell?id= 数值型**有回显**注入点（COPY 落表后需要 UNION 回显读结果，
//      盲点 /oob 走不了这条链路——os-shell 的标准形态就是「有回显点 + 多语句」）
//   3. 手工确认注入点（3 列，数值上下文）→ Exploiter.osShell('cmd /c echo <marker>')
//   4. 外部事实断言（不采信自报成功）：回显值必须包含 marker 令牌。
//
// 硬前提（与真机一致）：PG 连接用户需 superuser（COPY FROM PROGRAM 仅限）。
// 用法：node e2e/oob-real-lab/pg-osshell.e2e.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const pg = _require('pg');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Exploiter } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Exploiter.js')).href);
const { initDb, createOobLabApp } = await import(pathToFileURL(resolve(HERE, 'lab-app.mjs')).href);

const PORT = Number(process.env.PG_OSHELL_PORT) || 8271;
const BASE = `http://127.0.0.1:${PORT}`;

// 前置检查：PG 可连且为 superuser
const admin = new pg.Client({ host: '127.0.0.1', port: 5432, user: 'postgres', password: 'postgres', database: 'postgres' });
try {
  await admin.connect();
  const { rows } = await admin.query('SELECT rolsuper FROM pg_roles WHERE rolname = current_user');
  if (!rows[0]?.rolsuper) {
    console.log('[SKIP] PG 当前用户非 superuser → COPY FROM PROGRAM 不可用（这是 PG 的权限边界，非引擎缺陷）');
    await admin.end();
    process.exit(0);
  }
  console.log('[pre] PG superuser=ok @ 127.0.0.1:5432');
} catch (e) {
  console.log(`[SKIP] PG 不可连（${e.message}）—— 本机 5432 未起时属环境缺项`);
  process.exit(0);
}

// 1) 建库建表（与 oob 靶场同源）
await initDb();
console.log('[step1] oob_lab 库就绪（users 5 行种子）');

// 2) 起靶场：无 WAF 模式，走 /shell 有回显数值型点
const { app, close } = createOobLabApp({ waf: false });
const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[pg-osshell] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[step2] 靶场就绪 ${BASE}/shell?id=1`);

// 3) 扫描拿真实注入点（数值上下文 3 列，有回显 → union 列枚举/回显全链路真实走通）
const sm = new ScanManager();
const scanId = await sm.start({
  url: `${BASE}/shell?id=1`,
  config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false, techniques: ['union'] },
});
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 40));
}
const report = sm.getReport(scanId) || {};
const vuln = (report.vulns || [])[0];
const point = (report.points || []).find((p) => p.id === vuln?.pointId) || (report.points || [])[0];
if (!vuln || !point) {
  console.log('[FAIL] 扫描未检出 /shell 注入点（靶场/引擎异常，非 os-shell 范畴）');
  server.close(); await close(); await admin.end();
  process.exit(1);
}
console.log(`[step3] 注入点 ${point.id}（${vuln.technique}，boundary=${JSON.stringify(point.boundary)}，columns=${point.columns ?? '未确认'}）`);

const target = report.target || { url: BASE };
const ctx = {
  httpClient: sm.getScanClient(scanId, target),
  config: target.config || {},
  target,
  point,
  dbms: report.dbms || vuln?.dbms || 'PostgreSQL',
};

// 4) osShell 闭环：marker 必须原样回来（COPY FROM PROGRAM 落表 → UNION 回显读出）
const exploiter = new Exploiter();
const marker = `pgshell_${Date.now() % 100000}`;
const osRes = await exploiter.osShell(ctx, `cmd /c echo ${marker}`);
const outVal = String(osRes.value ?? '');
const ok = osRes.ok === true && outVal.includes(marker);
console.log(`[step4] osShell → ${JSON.stringify({ ok: osRes.ok, value: outVal.slice(0, 60), note: osRes.note ?? null, error: osRes.error ?? null })}`);
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] PG os-shell 真机闭环：COPY FROM PROGRAM 落表 → 回显 marker=${ok ? '命中' : '未命中'}`);

// 清理 cmd_out 表（保持靶场库整洁）
try { await admin.query('DROP TABLE IF EXISTS oob_lab.cmd_out'); } catch { /* noop */ }

server.close();
await close();
await admin.end();
process.exit(ok ? 0 : 1);

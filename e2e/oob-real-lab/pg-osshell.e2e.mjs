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
const { initDb, createOobLabApp, PG_CONF } = await import(pathToFileURL(resolve(HERE, 'lab-app.mjs')).href);

const PORT = Number(process.env.PG_OSHELL_PORT) || 8271;
const BASE = `http://127.0.0.1:${PORT}`;
const PG_REQUIRE = process.env.PG_REQUIRE === '1' || process.env.PG_REQUIRE === 'true';

// 前置检查：PG 可连且为 superuser
const admin = new pg.Client({ ...PG_CONF, database: 'postgres' });
try {
  await admin.connect();
  const { rows } = await admin.query('SELECT rolsuper FROM pg_roles WHERE rolname = current_user');
  if (!rows[0]?.rolsuper) {
    const msg = '[SKIP] PG 当前用户非 superuser → COPY FROM PROGRAM 不可用（这是 PG 的权限边界，非引擎缺陷）';
    console.log(msg);
    await admin.end();
    if (PG_REQUIRE) { console.error('[FAIL] PG_REQUIRE=1 但 superuser 不可用'); process.exit(1); }
    process.exit(0);
  }
  console.log(`[pre] PG superuser=ok @ ${PG_CONF.host}:${PG_CONF.port}`);
} catch (e) {
  const msg = `[SKIP] PG 不可连（${e.message}）—— 本机 ${PG_CONF.port} 未起时属环境缺项`;
  console.log(msg);
  if (PG_REQUIRE) { console.error('[FAIL] PG_REQUIRE=1 但 PG 不可连'); process.exit(1); }
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
  if (Date.now() - t0 > 120000) { sm.stop(scanId); break; }
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
// [2026-10-14 FIX] 命令必须按**执行方**（PG 服务所在宿主，本脚本与它同机）的平台选：
// PG 的 COPY ... FROM PROGRAM 由服务端 shell 执行，CI 的 acceptance 跑 ubuntu-latest，
// 而这里原本写死 Windows 的 `cmd /c echo` ⇒ Linux 上是 `cmd: not found` ⇒ COPY 失败、
// cmd_out 无行 ⇒ 回显空串；而 pgOsShell 无条件返回 ok:true ⇒ 表面只看到「marker 未命中」，
// 看不出到底是权限问题还是命令压根不存在。与 osShell.js 里 Oracle Java 分支同一口径。
// ⚠ 前提：PG 与脚本同机。若将来 PG 跑在远端/容器里，platform 要换成"PG 宿主平台"。
const shellCmd = process.platform === 'win32' ? `cmd /c echo ${marker}` : `echo ${marker}`;
const osRes = await exploiter.osShell(ctx, shellCmd);
const outVal = String(osRes.value ?? '');
const ok = osRes.ok === true && outVal.includes(marker);
console.log(`[step4] osShell（${shellCmd}）→ ${JSON.stringify({ ok: osRes.ok, value: outVal.slice(0, 60), note: osRes.note ?? null, error: osRes.error ?? null })}`);

if (!ok) {
  // 取证：把「COPY 压根没执行」与「执行了但回显通道没读出」分开，否则下次红还是只能猜。
  try {
    const exists = await admin.query("SELECT to_regclass('oob_lab.cmd_out') IS NOT NULL AS t");
    const tableExists = !!exists.rows[0]?.t;
    let rows = 'n/a';
    if (tableExists) {
      const n = await admin.query('SELECT count(*)::int AS n FROM oob_lab.cmd_out');
      rows = String(n.rows[0]?.n);
    }
    console.log(`[diag] cmd_out 表存在=${tableExists} 行数=${rows}（表不存在/0 行 ⇒ COPY 未执行，多半是命令或权限；有行 ⇒ 回显提取通道的问题）`);
  } catch (e) {
    console.log(`[diag] cmd_out 取证查询失败：${e.message}`);
  }
}
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] PG os-shell 真机闭环：COPY FROM PROGRAM 落表 → 回显 marker=${ok ? '命中' : '未命中'}`);

// 清理 cmd_out 表（保持靶场库整洁）
try { await admin.query('DROP TABLE IF EXISTS oob_lab.cmd_out'); } catch { /* noop */ }

server.close();
await close();
await admin.end();
process.exit(ok ? 0 : 1);

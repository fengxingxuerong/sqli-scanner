// ============================================================================
// e2e/concurrent-isolation/e2e.mjs —— 并发多扫描隔离性验证
// ============================================================================
// 实战视角：批量资产扫描时同一引擎进程会同时跑多个扫描任务。若限速桶/事件流/
// 缓存/扫描上下文在 scan 间串扰，会出现「A 目标的凭据打到 B 目标」「A 的结果混进
// B 的报告」这类交付事故。本 e2e 用真实双库（PG + MySQL）三个并发扫描验证：
//   ① 各扫描独立发现各自注入点（union 全命中）
//   ② 报告互不串扰（dbms/数据归属正确）
// 依赖：MySQL:3306（root/root，sqli_lab 库）+ PG:5432（postgres/postgres）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const mysql = _require('mysql2/promise');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { initDb, createOobLabApp } = await import(pathToFileURL(resolve(ROOT, 'e2e/oob-real-lab/lab-app.mjs')).href);
const { createMysqlLabApp } = await import(pathToFileURL(resolve(ROOT, 'e2e/real-mysql-lab/lab-app.js')).href);

const PG_PORT = Number(process.env.CONC_PG_PORT) || 8272;
const MY_PORT = Number(process.env.CONC_MY_PORT) || 8273;

// 1) 双靶场起服务
await initDb();
const { app: pgApp, close: pgClose } = createOobLabApp({ waf: false });
const pgServer = pgApp.listen(PG_PORT, '127.0.0.1');
const myPool = mysql.createPool({ host: '127.0.0.1', port: 3306, user: 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: 'sqli_lab', connectionLimit: 8 });
const myServer = createMysqlLabApp(myPool).listen(MY_PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  let n = 0;
  const done = () => { if (++n === 2) resolve(); };
  pgServer.once('listening', done);
  myServer.once('listening', done);
  pgServer.once('error', reject);
  myServer.once('error', reject);
});
console.log(`[setup] PG:${PG_PORT} + MySQL:${MY_PORT} 靶场就绪`);

// 2) 三个并发扫描（2 个 MySQL 不同上下文 + 1 个 PG，故意混库）
const sm = new ScanManager();
const targets = [
  { name: 'pg-shell', url: `http://127.0.0.1:${PG_PORT}/shell?id=1`, expectDbms: 'PostgreSQL' },
  { name: 'my-num', url: `http://127.0.0.1:${MY_PORT}/num?id=1`, expectDbms: 'MySQL' },
  { name: 'my-str', url: `http://127.0.0.1:${MY_PORT}/str?name=alice`, expectDbms: 'MySQL' },
];
const t0 = Date.now();
const started = await Promise.all(
  targets.map((t) => sm.start({ url: t.url, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union'] } }).then((id) => ({ ...t, id })))
);

for (;;) {
  const statuses = started.map((r) => sm.scans.get(r.id)?.status);
  if (statuses.every((s) => s === 'completed' || s === 'error')) break;
  if (Date.now() - t0 > 180000) { console.log('[FAIL] 并发扫描 180s 未全部完成'); break; }
  await new Promise((r) => setTimeout(r, 50));
}

// 3) 断言：各扫描独立命中 union + dbms 归属正确 + 互不串扰
let allOk = true;
for (const r of started) {
  const rep = sm.getReport(r.id) || {};
  const techs = [...new Set((rep.vulns || []).map((v) => v.technique))];
  const dbms = rep.dbms || (rep.vulns || [])[0]?.dbms || null;
  const unionOk = techs.includes('union');
  const dbmsOk = dbms === r.expectDbms;
  if (!unionOk || !dbmsOk) allOk = false;
  console.log(`[${r.name}] status=${sm.scans.get(r.id)?.status} dbms=${dbms}(期望 ${r.expectDbms}${dbmsOk ? '✓' : '✗'}) techs=${JSON.stringify(techs)} union=${unionOk ? 'OK' : 'MISS'}`);
}
console.log(`\n[${allOk ? 'PASS' : 'FAIL'}] 并发多扫描隔离性：各自命中 union、dbms 归属正确、互不串扰`);

pgServer.close();
myServer.close();
await myPool.end();
await pgClose();
process.exit(allOk ? 0 : 1);

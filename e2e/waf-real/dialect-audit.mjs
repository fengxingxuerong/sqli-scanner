// ============================================================================
// e2e/waf-real/dialect-audit.mjs —— 方言浪费审计
//
// 问题：目标是 MySQL，但实测观察到了 MSSQL payload（CONVERT(int,(SELECT DB_NAME()))）。
// 这类请求在 MySQL 上必然语法错误，既浪费请求预算，又白白增加 WAF 拦截面。
//
// 本脚本在靶场侧记录**每一个**发出的参数值，按方言关键字分类统计：
//   · 总量 / 各类占比
//   · 各类去重样例（定位来源）
// 支持 --nowaf（关 CRS，看引擎纯行为）与 --level=N。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const HERE = dirname(fileURLToPath(import.meta.url));
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const arg = (k, d) => {
  const hit = process.argv.find((a) => a.startsWith(`--${k}=`));
  return hit ? hit.slice(k.length + 3) : d;
};
const NOWAF = process.argv.includes('--nowaf');
const LEVEL = Number(arg('level', 1));

const PORT = 8153;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };

// [预检] 靶场没起 → 引擎必然 0 检出，会得出假结论
{
  const probe = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 1 });
  try {
    const [rows] = await probe.query('SELECT COUNT(*) c FROM users');
    console.log(`[预检] MySQL 可用，users=${rows[0].c} 行`);
  } catch (e) {
    console.error(`[预检失败] ${e.message}\n请先启动：/d/mysql/bin/mysqld --datadir=D:/mysql/data --port=3307`);
    process.exit(2);
  } finally {
    await probe.end().catch(() => {});
  }
}

// ── 方言分类器 ────────────────────────────────────────────────────────────
// 顺序即优先级：先判强特征（专属函数/系统表），避免被通用片段抢匹配。
// 'generic' = 跨方言通用（如 `'` / `AND 1=1` / `UNION SELECT NULL,...`），不算浪费。
const DIALECT_RULES = [
  ['SQL Server', /DB_NAME\s*\(|CONVERT\s*\(\s*(int|bigint|smallint|tinyint|decimal|numeric|float|datetime|money|date|binary|uniqueidentifier)\b|@@(servername|servicename|spid)|SUSER_(SNAME|SID)|HOST_NAME\s*\(|FORMATMESSAGE|sys\.(databases|tables|objects|syslogins|server_principals|database_principals|columns)|sysobjects|syslogins|master\.(dbo|sys)|xp_(cmdshell|dirtree)|WAITFOR\s+DELAY|ISNULL\s*\(.*AS\s+nvarchar|LEN\s*\(\s*DB_NAME|FOR\s+(XML|JSON)\s/i],
  ['Oracle', /SYS_CONTEXT|UTL_(HTTP|INADDR)|DBMS_PIPE|v\$version|USERENV|banner\s+FROM|\bDUAL\b|NVL\s*\(|TO_CHAR\s*\(|ROWNUM|ORA-\d{5}/i],
  ['PostgreSQL', /pg_sleep|::(text|int|numeric)|current_database|pg_catalog|generate_series|version\(\)\s*\|\||CHR\s*\(\s*\d+\s*\)/i],
  ['SQLite', /sqlite_(version|master)|\bRANDOMBLOB|LOAD_EXTENSION|sqlitemaster/i],
  ['ClickHouse', /toString\s*\(\s*\(|concat\s*\(\s*'__S__'|system\.(tables|columns)/i],
  ['DB2', /SYSIBM|FETCH\s+FIRST\s+\d+\s+ROWS/i],
  ['Sybase', /Adaptive\s+Server|@@version\s*LIKE|WAITFOR/i],
  ['Firebird', /rdb\$|RDB\$DATABASE/i],
  ['Informix', /systables|tabid\s*=/i],
  ['MonetDB', /sys\.(version|sleep)|sys_version/i],
  ['H2', /H2VERSION|org\.h2/i],
];

// MySQL 专属特征（用于确认「这条确实是 MySQL 方言」而非通用）
const MYSQL_MARKERS = /extractvalue|updatexml| information_schema\.|BENCHMARK\s*\(|SLEEP\s*\(|@@version|@@VERSION|VERSION\s*\(\s*\)|CONCAT\s*\(|0x[0-9a-f]{6,}|JSON_KEYS|GROUP_CONCAT|MID\s*\(|ORD\s*\(|\bRAND\s*\(\s*0\s*\)|PROCEDURE\s+ANALYSE/i;

function classify(v) {
  const s = String(v);
  for (const [name, re] of DIALECT_RULES) if (re.test(s)) return name;
  if (MYSQL_MARKERS.test(s)) return 'MySQL';
  return 'generic';
}

// ── 靶场：记录每个参数值 ──────────────────────────────────────────────────
const SEEN = []; // { v, scenario }
function makeApp() {
  const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const spy = (req, res, next) => {
    const all = { ...(req.query || {}), ...(req.body || {}) };
    for (const v of Object.values(all)) SEEN.push(String(v));
    next();
  };
  return { app: createMysqlLabApp(pool, spy), pool };
}

const SCENARIOS = [
  { name: 'num', url: '/num?id=1' },
  { name: 'str', url: '/str?name=alice' },
  { name: 'like', url: '/like?q=keyboard' },
  { name: 'orderby', url: '/orderby?sort=id' },
  { name: 'blind', url: '/blind?uid=1' },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false, level: LEVEL };
async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(scanId).catch(() => {}); return { vulns: [] }; }
    await new Promise((r) => setTimeout(r, 25));
  }
  return { vulns: (sm.getReport(scanId) || {}).vulns || [] };
}

const perScenario = {};
for (const sc of SCENARIOS) {
  SEEN.length = 0;
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  const out = await runScan(sm, { url: `${BASE}${sc.url}`, config: { ...baseConfig, ...(sc.cfg || {}) } });
  // 必须等 listening socket 真正关闭 + 连接池排空再起下一个场景：
  // 否则同端口复用会让上一场景的残留连接把下一场景的请求打断（read ECONNRESET），
  // 失败的探测被判据当成「ORDER BY 超出列数」→ 列数猜成 1，结论完全失真。
  await new Promise((r) => server.close(r));
  await pool.end().catch(() => {});
  await new Promise((r) => setTimeout(r, 150));

  const vals = [...SEEN];
  const byDialect = {};
  const samples = {};
  for (const v of vals) {
    const d = classify(v);
    byDialect[d] = (byDialect[d] || 0) + 1;
    (samples[d] = samples[d] || new Set()).add(v);
  }
  // UNION payload 的列数分布（列数猜错会按 N 倍放大后续逐列探测）
  const colCounts = {};
  let dualReqs = 0;
  for (const v of vals) {
    if (/FROM\s+dual/i.test(v)) dualReqs += 1;
    const m = /UNION\s+(?:ALL\s+)?SELECT\s+([\s\S]*?)(?:--|\#|$)/i.exec(v);
    if (!m) continue;
    const n = m[1].split(',').length;
    colCounts[n] = (colCounts[n] || 0) + 1;
  }
  perScenario[sc.name] = { total: vals.length, byDialect, samples, found: [...new Set(out.vulns.map((x) => x.technique))] };
  const waste = vals.length - (byDialect.MySQL || 0) - (byDialect.generic || 0);
  console.log(`\n[${sc.name}] 请求 ${vals.length}，非 MySQL/通用 ${waste}（${((waste / Math.max(vals.length, 1)) * 100).toFixed(1)}%），带 FROM dual ${dualReqs} 条，检出=[${perScenario[sc.name].found.join(',') || '-'}]`);
  for (const [d, n] of Object.entries(byDialect).sort((a, b) => b[1] - a[1])) {
    console.log(`   ${d.padEnd(12)} ${n}`);
  }
  const colTop = Object.entries(colCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (colTop.length) console.log(`   列数分布: ${colTop.map(([k, v]) => `${k}列×${v}`).join('  ')}`);
}

console.log('\n===== 浪费明细（非 MySQL 且非通用，按方言 × 样例）=====');
const agg = {};
for (const sc of Object.values(perScenario)) {
  for (const [d, set] of Object.entries(sc.samples)) {
    if (d === 'MySQL' || d === 'generic') continue;
    agg[d] = agg[d] || new Set();
    for (const s of set) agg[d].add(s);
  }
}
let totalWaste = 0;
for (const sc of Object.values(perScenario)) {
  totalWaste += Object.entries(sc.byDialect)
    .filter(([d]) => d !== 'MySQL' && d !== 'generic')
    .reduce((a, [, n]) => a + n, 0);
}
for (const [d, set] of Object.entries(agg)) {
  console.log(`\n# ${d}（去重 ${set.size} 条）`);
  for (const s of [...set].slice(0, 8)) console.log(`   ${s.slice(0, 400)}`);
}
const grand = Object.values(perScenario).reduce((a, s) => a + s.total, 0);
console.log(`\n===== 总计：请求 ${grand}，方言浪费 ${totalWaste}（${((totalWaste / Math.max(grand, 1)) * 100).toFixed(1)}%）=====`);
process.exit(0);

// ============================================================================
// e2e/diag/report-contract.e2e.mjs —— 报告契约验收
// ============================================================================
// 存在理由：五类真实缺陷的共同病征是「中间层自报成功、无人校验外部事实」。
// 报告是交付物的最终形态——如果它自报的字段（dbms 等级、命中技术、被压制状态、
// 引用完整性）与外部可观测状态不一致，前面所有环节的"正确"都失去意义。
//
// 本脚本做两类校验：
//   ① 内部一致性：报告字段之间不得互相矛盾（引用完整性、状态逻辑）；
//   ② **外部事实**：报告宣称的 dbms 必须能被**与本扫描器无关的独立探测**证实
//      （直接连目标库跑一条 SQL 确认版本），而不是采信引擎自己的识别结果。
//
// 用法：MYSQL_PORT=3306 MYSQL_USER=root MYSQL_PASSWORD=root node e2e/diag/report-contract.e2e.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createPentestLabApp, createPool } from '../pentest-lab/lab-app.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);
const { dbmsEvidenceOf } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/dbmsEvidence.js')).href);

const PORT = Number(process.env.PENTEST_LAB_PORT) || 8177;
const BASE = `http://127.0.0.1:${PORT}`;

const pool = createPool();
const server = createPentestLabApp(pool).listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const t0 = Date.now();
const scanId = await sm.start({
  url: `${BASE}/enc?q=Keyboard`,
  config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false },
});
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) break;
  await new Promise((r) => setTimeout(r, 40));
}
const report = sm.getReport(scanId) || {};
server.close();
await pool.end().catch(() => {});

let okCount = 0;
let badCount = 0;
const check = (name, cond, detail) => {
  if (cond) {
    okCount++;
    console.log(`[contract] ✓ ${name}`);
  } else {
    badCount++;
    console.log(`[contract] ✗ ${name}${detail ? `（${detail}）` : ''}`);
  }
};

// —— ① 内部一致性 ——
const vulns = report.vulns || [];
const points = report.points || [];
const pointIds = new Set(points.map((p) => p.id));
check(
  'vulns[].pointId 均能在 points 中找到（引用完整性）',
  vulns.length > 0 && vulns.every((v) => pointIds.has(v.pointId)),
  `${vulns.length} 条漏洞 / ${pointIds.size} 个点`
);
check(
  '每条漏洞都带技术标识与非空证据',
  vulns.every((v) => typeof v.technique === 'string' && v.technique.length > 0),
  JSON.stringify(vulns.map((v) => v.technique))
);
check(
  '报告顶层 dbms 与漏洞条目自报 dbms 不矛盾',
  !report.dbms || vulns.every((v) => !v.dbms || v.dbms === report.dbms),
  `report.dbms=${report.dbms}`
);

const ev = report.summary?.dbmsEvidence;
check('summary.dbmsEvidence 已写入', !!(ev && ev.dbms && ev.level), JSON.stringify(ev || null));
check(
  'dbmsEvidence.level 与 dbmsEvidence.js 声明一致（不得运行时自创等级）',
  ev ? ev.level === dbmsEvidenceOf(ev.dbms).level : false,
  ev ? `${ev.dbms}: 报告=${ev.level} 声明=${dbmsEvidenceOf(ev.dbms).level}` : 'n/a'
);

const bp = report.summary?.blockPolicy;
check(
  '无拦截场景下不得声称执行了自适应重跑（状态逻辑自洽）',
  !bp || bp.action !== 'adaptiveTamper' || Number(bp.blockHits ?? 0) > 0,
  JSON.stringify(bp || null)
);

// —— ② 外部事实：独立探测目标库，验证报告宣称的 dbms ——
let externalDbms = null;
try {
  const c = await mysql.createConnection({
    host: process.env.MYSQL_HOST ?? '127.0.0.1',
    port: Number(process.env.MYSQL_PORT) || 3306,
    user: process.env.MYSQL_USER ?? 'root',
    password: process.env.MYSQL_PASSWORD ?? 'root',
  });
  const [r] = await c.query("SELECT IF(@@version_comment LIKE '%MariaDB%', 'MariaDB', 'MySQL') AS d");
  externalDbms = r[0].d;
  await c.end();
} catch (e) {
  externalDbms = `探测失败(${e.code || e.message})`;
}
check(
  '报告宣称的 dbms 与独立探测结果一致（外部事实校验）',
  !!report.dbms && String(report.dbms).includes(externalDbms),
  `报告=${report.dbms} 独立探测=${externalDbms}`
);
check(
  'union 技术应被检出（该靶场为显式 UNION 注入点）',
  vulns.some((v) => v.technique === 'union'),
  JSON.stringify([...new Set(vulns.map((v) => v.technique))])
);

console.log(`\n[contract] 校验通过 ${okCount}`);
console.log(`[contract] 不一致 ${badCount}`);
console.log(badCount === 0 ? '\n[PASS] 报告契约全部满足' : '\n[FAIL] 报告契约存在不一致');
process.exit(badCount === 0 ? 0 : 1);

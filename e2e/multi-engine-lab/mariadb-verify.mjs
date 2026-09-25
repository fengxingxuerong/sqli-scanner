// ============================================================================
// e2e/multi-engine-lab/mariadb-verify.mjs —— MariaDB 11.4.13 真实引擎 tamper A/B
// 用法：node e2e/multi-engine-lab/mariadb-verify.mjs
// 前置：MariaDB @ 127.0.0.1:3308（root 无密码，sqli_lab 库已建）
// 结构与 waf-real/waf-verify.mjs 同构（同场景同 CRS），唯一差异是目标引擎换 MariaDB，
// 结果可与 MySQL 8.0.28 横向对比（dash2hash 的 dbms 白名单含 MariaDB，应同样生效）。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../waf-real/crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { createMysqlLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../real-mysql-lab/lab-app.js')).href);

const PORT = 8151;
const BASE = `http://127.0.0.1:${PORT}`;
const MARIADB_CONF = { host: '127.0.0.1', port: Number(process.env.MARIADB_PORT) || 3308, user: 'root', password: '', database: 'sqli_lab' };

let WAF_HITS = 0;
function makeApp() {
  const pool = mysql.createPool({ ...MARIADB_CONF, connectionLimit: 8, multipleStatements: true });
  const crsMiddleware = (req, res, next) => {
    const verdict = evaluate(fromExpress(req));
    if (verdict.blocked) {
      WAF_HITS++;
      res.status(403).send(`<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
      return;
    }
    next();
  };
  const app = createMysqlLabApp(pool, crsMiddleware);
  return { app, pool };
}

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [] }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [] };
}
const techs = (v) => [...new Set((v || []).map((x) => x.technique))];

const SCENARIOS = [
  { name: 'num', url: '/num?id=1', must: ['boolean'] },
  { name: 'str', url: '/str?name=alice', must: ['boolean'] },
  { name: 'like', url: '/like?q=keyboard', must: ['boolean'] },
  { name: 'orderby', url: '/orderby?sort=id', must: ['boolean'], cfg: { level: 2 } },
  { name: 'blind', url: '/blind?uid=1', must: ['boolean'] },
  { name: 'safe', url: '/safe?id=1', expectSafe: true },
  { name: 'echo', url: '/echo?key=abc', expectSafe: true },
];

const TAMPERS = {
  off: null,
  on: { tamper: { enabled: true, plugins: ['dash2hash'], intensity: 'medium' } },
};

// [TARGET-GUARD 2026-09-25] 3308 这个端口在本仓有**两个主人**：真 MariaDB 便携版（本套件的靶的）
//   和 `e2e/udf-lab/mysql_sandbox.py` 起的隔离 **MySQL 8** 沙箱（run-all 里 'sandbox' 类依赖走它）。
//   两者同端口同库名，脚本连上就跑 ⇒ 沙箱在的时候跑一次，就会把 **MySQL 8 的数字**
//   写进 `mariadb-report.md` 并标注"MariaDB 11.4.13" —— 那是凭空造出来的假证据，而且看起来完全可信。
//   所以开跑前读一次服务端自报版本，不是 MariaDB 就硬退（这不是"环境没配好"的 SKIP，是指错对象）。
{
  let who = '';
  try {
    const c = await mysql.createConnection({ ...MARIADB_CONF, connectionLimit: 1 });
    try {
      const [[v]] = await c.query('SELECT VERSION() AS v, @@version_comment AS cm');
      who = `${v.v} ${v.cm || ''}`.trim();
    } finally {
      await c.end().catch(() => {});
    }
  } catch (e) {
    console.error(`[mariadb-verify] 拒绝开跑：连不上 ${MARIADB_CONF.host}:${MARIADB_CONF.port} 的 MariaDB（${e.code || e.message}）。`);
    console.error('  期望该端口上是 MariaDB（root 无密码，库 sqli_lab）。');
    console.error('  注意 3308 也会被 e2e/udf-lab 的 MySQL 沙箱占用 —— 那是另一个引擎，别用它的数字。');
    process.exit(2);
  }
  if (!/mariadb/i.test(who)) {
    console.error(`[mariadb-verify] 拒绝开跑：3308 上跑的是「${who}」，不是 MariaDB。`);
    console.error('  多半是 e2e/udf-lab 的 MySQL 沙箱占着 3308。本套件的产物名与 README 结论都写着 MariaDB，');
    console.error('  拿 MySQL 的数字去填就是假证据 ⇒ 先停掉沙箱，或把 MariaDB 换端口后用 MARIADB_PORT= 指过去。');
    process.exit(2);
  }
  console.log(`[mariadb-verify] 目标确认：${who}`);
}

// 结论列按**集合**判，不按长度判（与 waf-verify.mjs / multi-engine verify.mjs 同一批修）：
//   `on.length > off.length ⇒ 绕过生效` 会让 off=[boolean] / on=[boolean] 印成"绕过生效"
//   —— 入库那份 mariadb-report.md 的 num / blind 两行就是这个形状（2026-09-09 生成）。
function verdictOf(offArr, onArr) {
  const gained = onArr.filter((t) => !offArr.includes(t));
  const lost = offArr.filter((t) => !onArr.includes(t));
  if (!offArr.length && !onArr.length) return '全拦';
  const parts = [];
  if (gained.length) parts.push(`绕过生效（新增 ${gained.join(',')}）`);
  if (lost.length) parts.push(`反而丢失 ${lost.join(',')}`);
  return parts.length ? parts.join('；') : '技术位持平';
}

const matrix = {};
for (const [label, tamper] of Object.entries(TAMPERS)) {
  WAF_HITS = 0;
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  const rows = {};
  for (const sc of SCENARIOS) {
    const cfg = { ...baseConfig, ...(sc.cfg || {}) };
    if (tamper) cfg.wafEvasion = { ...tamper };
    const before = WAF_HITS;
    const out = await runScan(sm, { url: `${BASE}${sc.url}`, config: cfg });
    rows[sc.name] = { found: techs(out.vulns), wafBlocked: WAF_HITS - before, status: out.status };
  }
  server.close();
  await pool.end().catch(() => {});
  matrix[label] = rows;
  const det = SCENARIOS.filter((s) => !s.expectSafe).filter((s) => rows[s.name].found.length > 0).length;
  console.log(`[tamper ${label}] 检出场景 ${det}/5，WAF 拦截 ${WAF_HITS} 次`);
  for (const sc of SCENARIOS) {
    console.log(`  ${sc.name.padEnd(8)} 检出=[${rows[sc.name].found.join(',') || '-'}]  被WAF拦 ${rows[sc.name].wafBlocked}`);
  }
}

console.log('\n===== MariaDB 11.4.13 A/B 汇总 =====');
for (const sc of SCENARIOS.filter((s) => !s.expectSafe)) {
  const off = matrix.off[sc.name].found;
  const on = matrix.on[sc.name].found;
  console.log(`${sc.name.padEnd(8)} tamper off: ${off.join(',') || '-'}  tamper on: ${on.join(',') || '-'}  ${verdictOf(off, on)}`);
}
const safeOk = SCENARIOS.filter((s) => s.expectSafe).every((s) => matrix.off[s.name].found.length === 0 && matrix.on[s.name].found.length === 0);
console.log(`安全对照误拦：${safeOk ? '无 ✅' : '有 ❌'}`);

const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
writeFileSync(resolve(RESULTS_DIR, 'mariadb-report.json'), JSON.stringify({ generatedAt: genAt, engine: 'MariaDB 11.4.13 @3308', matrix }, null, 2));
const md = [
  '# MariaDB 11.4.13 真实引擎 tamper A/B（CRS v4.1.0）',
  '',
  `> 生成：${genAt}　｜　靶场：真实 MariaDB 11.4.13（e2e/real-mysql-lab/lab-app 连 3308）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3`,
  '',
  '| 场景 | tamper off | tamper on | 结论 |',
  '|---|---|---|---|',
  ...SCENARIOS.filter((s) => !s.expectSafe).map((s) => {
    const offArr = matrix.off[s.name].found;
    const onArr = matrix.on[s.name].found;
    return `| ${s.name} | ${offArr.join(',') || '-'} | ${onArr.join(',') || '-'} | ${verdictOf(offArr, onArr)} |`;
  }),
  '',
  `安全对照误拦：${safeOk ? '无' : '有（需修）'}`,
].join('\n');
writeFileSync(resolve(RESULTS_DIR, 'mariadb-report.md'), md);
console.log(`[report] ${RESULTS_DIR}`);

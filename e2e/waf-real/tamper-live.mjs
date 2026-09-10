// ============================================================================
// e2e/waf-real/tamper-live.mjs —— tamper 链在「真实 MySQL + CRS v4.1.0」下的动态 A/B
// 与 tamper-sweep.mjs（静态）互补：
//   · 静态只看 CRS 是否拦截 → 语义破坏型编码（base64/hex）会假性 6/6
//   · 动态同时要求「引擎仍检出」→ 只有绕过且注入仍生效才算有效
// 同时抓取被拦 payload 原文 + 规则号，用于定位到底是哪条规则在卡。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const HERE = dirname(fileURLToPath(import.meta.url));
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const PORT = 8151;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };

// [预检] MySQL 未起时靶场返回 500，引擎必然 0 检出 —— 会导致「tamper 无效」的假结论。
// 曾因此白跑一轮 1m43s，故开局强制连通性校验，失败立即退出。
{
  const probe = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 1 });
  try {
    const [rows] = await probe.query('SELECT COUNT(*) c FROM users');
    console.log(`[预检] MySQL ${MYSQL_CONF.host}:${MYSQL_CONF.port} 可用，users=${rows[0].c} 行`);
  } catch (e) {
    console.error(`[预检失败] MySQL 不可用：${e.message}\n请先启动：/d/mysql/bin/mysqld --datadir=D:/mysql/data --port=3307`);
    process.exit(2);
  } finally {
    await probe.end().catch(() => {});
  }
}

let BLOCKS = []; // { value, ruleId }
function makeApp() {
  const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const crsMiddleware = (req, res, next) => {
    const verdict = evaluate(fromExpress(req));
    if (verdict.blocked) {
      const all = { ...(req.query || {}), ...(req.body || {}) };
      BLOCKS.push({ value: Object.values(all).map(String).join(' | ').slice(0, 160), ruleId: verdict.ruleId });
      res.status(403).send(`<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403</h1><p>Blocked by CRS ${verdict.ruleId}</p></body></html>`);
      return;
    }
    next();
  };
  return { app: createMysqlLabApp(pool, crsMiddleware), pool };
}

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); return { vulns: [] }; }
    await new Promise((r) => setTimeout(r, 25));
  }
  return { vulns: (sm.getReport(scanId) || {}).vulns || [] };
}
const techs = (v) => [...new Set((v || []).map((x) => x.technique))];

const SCENARIOS = [
  { name: 'num', url: '/num?id=1' },
  { name: 'str', url: '/str?name=alice' },
  { name: 'like', url: '/like?q=keyboard' },
  { name: 'orderby', url: '/orderby?sort=id', cfg: { level: 2 } },
  { name: 'blind', url: '/blind?uid=1' },
];

const CHAINS = {
  off: null,
  dash2hash: ['dash2hash'],
  hexliterals: ['hexliterals'],
  'd2h+hexliterals': ['dash2hash', 'hexliterals'],
};

const result = {};
for (const [label, plugins] of Object.entries(CHAINS)) {
  BLOCKS = [];
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  const rows = {};
  for (const sc of SCENARIOS) {
    const cfg = { ...baseConfig, ...(sc.cfg || {}) };
    if (plugins) cfg.wafEvasion = { tamper: { enabled: true, plugins, intensity: 'medium' } };
    const before = BLOCKS.length;
    const out = await runScan(sm, { url: `${BASE}${sc.url}`, config: cfg });
    rows[sc.name] = { found: techs(out.vulns), blocked: BLOCKS.length - before };
  }
  // 等 listening socket 真正关闭 + 连接池排空（否则同端口复用会打断下一链的请求，
  // 失败探测会被判据误读成「ORDER BY 超出列数」，列数猜错 → 结论失真）
  await new Promise((r) => server.close(r));
  await pool.end().catch(() => {});
  await new Promise((r) => setTimeout(r, 150));
  result[label] = rows;

  const det = SCENARIOS.filter((s) => rows[s.name].found.length > 0).length;
  console.log(`\n[${label}] 检出场景 ${det}/${SCENARIOS.length}，被拦请求 ${BLOCKS.length}`);
  for (const sc of SCENARIOS) {
    console.log(`   ${sc.name.padEnd(8)} 检出=[${rows[sc.name].found.join(',') || '-'}]  拦 ${rows[sc.name].blocked}`);
  }
  const byRule = {};
  for (const b of BLOCKS) byRule[b.ruleId] = (byRule[b.ruleId] || 0) + 1;
  console.log(`   规则分布: ${Object.entries(byRule).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}×${v}`).join(' ')}`);
  const seen = new Set();
  const samples = BLOCKS.filter((b) => (seen.has(b.ruleId) ? false : (seen.add(b.ruleId), true))).slice(0, 6);
  for (const s of samples) console.log(`     例 ${s.ruleId}: ${s.value}`);
}

console.log('\n===== 汇总（检出技术位总数）=====');
for (const label of Object.keys(CHAINS)) {
  const total = SCENARIOS.reduce((a, s) => a + result[label][s.name].found.length, 0);
  const blk = SCENARIOS.reduce((a, s) => a + result[label][s.name].blocked, 0);
  console.log(`${label.padEnd(16)} 技术位 ${total}  被拦请求 ${blk}`);
}
process.exit(0);

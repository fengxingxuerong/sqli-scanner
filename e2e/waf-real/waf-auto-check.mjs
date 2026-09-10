// ============================================================================
// e2e/waf-real/waf-auto-check.mjs —— CRS 下「引擎自动绕过」验收（不显式配 tamper）
// ============================================================================
// 与 waf-verify.mjs 的区别：那一份测「人工挂链」，本份测「引擎自己能不能挂对链」。
// 验收点：真实 CRS v4.1.0 规则下，config 不含 wafEvasion.tamper，仅靠
//   拦截证据驱动（wafEvasion.adaptiveOnBlock）+ 链验证 → 自动选出有效链并重跑。
// 期望：检出技术位 ≥ 人工挂 dash2hash 的一半，且安全对照零误拦。
// 用法：MYSQL_PORT=3306 MYSQL_USER=root node e2e/waf-real/waf-auto-check.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const HERE = dirname(fileURLToPath(import.meta.url));
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const PORT = 8153;
const MYSQL_CONF = {
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};

let WAF_HITS = 0;
const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
const crsMiddleware = (req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    WAF_HITS++;
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><p>blocked by CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
};
const app = createMysqlLabApp(pool, crsMiddleware);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${PORT}`;

const SCENARIOS = [
  { name: 'num', url: '/num?id=1' },
  { name: 'str', url: '/str?name=alice' },
  { name: 'like', url: '/like?q=keyboard' },
  { name: 'orderby', url: '/orderby?sort=id', cfg: { level: 2 } },
  { name: 'blind', url: '/blind?uid=1' },
];
const SAFE = [
  { name: 'safe', url: '/safe?id=1' },
  { name: 'echo', url: '/echo?key=abc' },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
const sm = new ScanManager();

async function runScan(target) {
  const t0 = Date.now();
  const id = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(id).catch(() => {}); return { techs: [], report: {}, ms: Date.now() - t0 }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(id) || {};
  return { techs: [...new Set((rep.vulns || []).map((v) => v.technique))], report: rep, ms: Date.now() - t0 };
}

const rows = [];
let bits = 0;
for (const sc of SCENARIOS) {
  const out = await runScan({ url: BASE + sc.url, config: { ...baseConfig, ...(sc.cfg || {}) } });
  const wafAdaptive = out.report?.summary?.wafAdaptive || null;
  bits += out.techs.length;
  rows.push({ ...sc, techs: out.techs, ms: out.ms, wafAdaptive });
  console.log(
    `[auto] ${sc.name.padEnd(8)} 检出=[${out.techs.join(',') || '-'}] 耗时=${out.ms}ms` +
      (wafAdaptive ? `  自适应=${wafAdaptive.triggered ? '触发' : '-'}` : '')
  );
}
let falsePositive = 0;
for (const sc of SAFE) {
  const out = await runScan({ url: BASE + sc.url, config: baseConfig });
  if (out.techs.length) falsePositive++;
  console.log(`[auto] ${sc.name.padEnd(8)} 检出=[${out.techs.join(',') || '-'}]（期望空）`);
}

server.close();
await pool.end().catch(() => {});
mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(
  resolve(HERE, 'results', 'waf-auto-check.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), wafHits: WAF_HITS, techBits: bits, safeFalsePositive: falsePositive, rows }, null, 2)
);
console.log(`\n[auto] 自动绕过技术位合计 ${bits}（人工 dash2hash 基线 = 10）｜WAF 拦截 ${WAF_HITS} 次｜安全误报 ${falsePositive}`);
console.log('[auto] 结论：' + (bits >= 5 ? '自动路径生效 ✅' : '自动路径未生效 ❌'));
process.exit(0);

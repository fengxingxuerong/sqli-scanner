// 诊断：用真实 lab-app（MySQL 3307 + CRS）复现 /echo 误报
// 与 waf-verify 唯一差异：只扫 echo（排除前置 6 场景的负载/状态影响）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { createMysqlLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../real-mysql-lab/lab-app.js')).href);

const PORT = 8163;
const MYSQL_CONF = { host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' };
const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
let WAF_HITS = 0;
const crsMiddleware = (req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    WAF_HITS++;
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
};
const app = createMysqlLabApp(pool, crsMiddleware);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

for (const run of [1, 2]) {
  const sm = new ScanManager();
  const scanId = await sm.start({ url: `http://127.0.0.1:${PORT}/echo?key=abc`, config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false } });
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  const v = rep.vulns || [];
  console.log(`run#${run}: vulns=${v.length} WAF_HITS=${WAF_HITS}`);
  for (const x of v) {
    console.log('  technique:', x.technique, '| param:', x.param || x.pointId);
    console.log('  full vuln:', JSON.stringify(x).slice(0, 900));
  }
}
server.close();
await pool.end().catch(() => {});
process.exit(0);

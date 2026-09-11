// 诊断：/num 真阳性在 CRS 下被误杀的定位（tamper off，对应 waf-real off 档 2/5→0/5 回归）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { createMysqlLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../real-mysql-lab/lab-app.js')).href);

const PORT = 8165;
const MYSQL_CONF = { host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' };
const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
const crsMiddleware = (req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
};
const app = createMysqlLabApp(pool, crsMiddleware);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const scanId = await sm.start({ url: `http://127.0.0.1:${PORT}/num?id=1`, config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false, adaptiveOnBlock: false } });
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 30));
}
const rep = sm.getReport(scanId) || {};
const v = rep.vulns || [];
console.log('status:', sm.scans.get(scanId)?.status, '| vulns:', v.length);
for (const x of v) {
  console.log('  technique:', x.technique, '| payloads:', JSON.stringify(x.payloads));
  console.log('  evidence:', String(x.evidence || '').slice(0, 200));
}
server.close();
await pool.end().catch(() => {});
process.exit(0);

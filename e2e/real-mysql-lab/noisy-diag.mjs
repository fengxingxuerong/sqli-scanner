// [todo#38] /noisy 单点诊断：检出证据 + dbms 误判（DM8）来源
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
import { createMysqlLabApp } from './lab-app.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const { ScanManager } = await import(
  pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href
);

const PORT = 8141;
const BASE = `http://127.0.0.1:${PORT}`;

const mysql = require('mysql2/promise');
const pool = mysql.createPool({ host: '127.0.0.1', port: 3306, user: 'root', password: 'root', database: 'sqli_lab', connectionLimit: 4 });
const app = createMysqlLabApp(pool);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const scanId = await sm.start({ url: `${BASE}/noisy?uid=1` });
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 30));
}
const rep = sm.getReport(scanId) || {};
console.log('=== /noisy vulns ===');
for (const v of rep.vulns || []) {
  console.log(`tech=${v.technique} dbms=${v.dbms}`);
  console.log(`  evidence: ${String(v.evidence || '').slice(0, 160)}`);
  console.log(`  payload : ${String((v.payloads || [])[0] || '').slice(0, 120)}`);
}
console.log('=== summary.dbmsEvidence ===');
console.log(JSON.stringify(rep.summary?.dbmsEvidence ?? null, null, 1).slice(0, 900));
server.close();
await pool.end();
process.exit(0);

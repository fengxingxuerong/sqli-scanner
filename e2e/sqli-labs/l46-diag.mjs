// [todo#39] L46 单点复测诊断：ORDER BY 注入未检出根因
import { ScanManager } from '../../server/src/engine/ScanManager.js';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = 8130;
const BASE = `http://127.0.0.1:${PORT}`;

// 独立拉起靶场（与 runner 相同方式）
const lab = spawn('python', ['e2e/sqli-labs/sqli-labs.py'], { stdio: 'ignore' });
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  try { await fetch(`${BASE}/Less-1/?id=1`); up = true; } catch { await sleep(300); }
}
if (!up) { console.error('lab not up'); process.exit(1); }

const sm = new ScanManager();
const baseConfig = {
  concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000,
  techniques: ['union', 'error', 'boolean', 'time', 'stacked', 'inline'],
  enableExtract: false, level: 2,
};
const scanId = await sm.start({ url: `${BASE}/Less-46/?sort=id`, ...baseConfig });
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 90000) { sm.stop(scanId).catch(() => {}); break; }
  await sleep(50);
}
const rep = sm.getReport(scanId) || {};
console.log('vulns:', (rep.vulns || []).map((v) => `${v.technique}:${String(v.evidence || '').slice(0, 80)}`));
console.log('dbmsEvidence:', JSON.stringify(rep.summary?.dbmsEvidence?.dbms ?? null));
console.log('requests:', rep.summary?.requests ?? rep.stats?.requests ?? '?');
console.log('points:', (rep.summary?.points ?? rep.points ?? []).length || JSON.stringify(rep.summary?.points || rep.points || []).slice(0, 200));
lab.kill();
process.exit(0);

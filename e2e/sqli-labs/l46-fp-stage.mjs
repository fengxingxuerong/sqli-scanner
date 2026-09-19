// [todo#39] L46 DBFingerprinter 逐阶段诊断 v2：定位 Sybase 误定库来源
import { DBFingerprinter } from '../../server/src/engine/DBFingerprinter.js';
import { TargetParser } from '../../server/src/engine/TargetParser.js';
import { createTarget } from '../../server/src/engine/models.js';
import { HttpClient } from '../../server/src/core/httpClient.js';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = 8130;
const BASE = `http://127.0.0.1:${PORT}`;

const lab = spawn('python', ['e2e/sqli-labs/sqli-labs.py'], { stdio: 'ignore' });
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  try { await fetch(`${BASE}/Less-1/?id=1`); up = true; } catch { await sleep(300); }
}
if (!up) { console.error('lab not up'); lab.kill(); process.exit(1); }

const httpClient = new HttpClient({ timeoutMs: 15000 });
const target = createTarget({ url: `${BASE}/Less-46/?sort=id` });
const parser = new TargetParser(httpClient);
const points = await parser.discover(target, httpClient);
const point = (points || [])[0];
console.log('points:', (points || []).length, 'point:', JSON.stringify({ url: point?.url, param: point?.param, location: point?.location, originalValue: point?.originalValue }));

const ctx = { httpClient, target, point, config: { concurrency: 2, timeoutMs: 15000 } };
const fp = new DBFingerprinter();
const t0 = Date.now();
const result = await fp.fingerprint(ctx);
console.log(`fingerprint → dbms=${result.dbms} version=${JSON.stringify(result.version)} 耗时=${Date.now() - t0}ms`);

const obf = (s) => s;
const errDbms = await fp._fingerprintByError(ctx, httpClient, target, point, obf);
console.log('_fingerprintByError →', errDbms);
const timeDbms = await fp._fingerprintByTime(ctx, httpClient, target, point, obf, {}, 20);
console.log('_fingerprintByTime →', timeDbms);

await httpClient.close?.()?.catch?.(() => {});
lab.kill();
process.exit(0);

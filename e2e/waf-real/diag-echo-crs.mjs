// 诊断：/echo 安全对照在 CRS 下的 boolean 误报精确复现
// 与 diag-echo-fp.mjs 唯一差异：加 CRS 中间件（复现 waf-real 环境）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);

const PORT = 8162;
let WAF_HITS = 0;
const app = express();
app.use((req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    WAF_HITS++;
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
});
app.get('/echo', (req, res) => {
  const key = String(req.query.key ?? '');
  res.send(`<!DOCTYPE html><html><head><title>Echo</title></head><body><p>key = ${key.replace(/</g, '&lt;')}</p></body></html>`);
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

for (const run of [1, 2, 3]) {
  const sm = new ScanManager();
  const scanId = await sm.start({ url: `http://127.0.0.1:${PORT}/echo?key=abc`, config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 10000, enableExtract: false } });
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
    console.log('  evidence:', String(x.evidence || x.description || '').slice(0, 220));
    const payload = x.payload || x.proofPayload || (x.details && x.details.payload);
    if (payload) console.log('  payload:', String(payload).slice(0, 120));
  }
}
server.close();
process.exit(0);

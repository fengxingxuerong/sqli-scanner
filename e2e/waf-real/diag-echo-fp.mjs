// 诊断：/echo 安全对照的 boolean 误报复现（无 WAF，排除 WAF 拦截差异干扰）
// 单独扫 /echo，打出全部 vulns 明细（payload/evidence），定位是哪一对真假条件触发
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);

const PORT = 8161;
const app = express();
app.get('/echo', (req, res) => {
  const key = String(req.query.key ?? '');
  res.send(`<!DOCTYPE html><html><head><title>Echo</title></head><body><p>key = ${key.replace(/</g, '&lt;')}</p></body></html>`);
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

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
console.log('status:', sm.scans.get(scanId)?.status);
console.log('vulns:', JSON.stringify(rep.vulns, null, 2));
console.log('summary.techniques:', JSON.stringify(rep.summary?.techniques || {}));
server.close();
process.exit(0);

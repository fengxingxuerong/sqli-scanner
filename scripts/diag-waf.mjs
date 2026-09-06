import { createLabApp } from '../e2e/waf-lab/lab-server.js';
import { httpClient } from '../server/src/core/httpClient.js';
import { obfuscateWithConfig } from '../server/src/core/tamper/applyTampers.js';

const app = createLabApp();
const server = app.listen(8099);
await new Promise((r) => { if (server.listening) return r(); server.once('listening', r); });

const rawPayload = "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'";
const ctx = { config: { wafEvasion: { tamper: { enabled: true, plugins: ['space2comment', 'charencode'], intensity: 'medium' } } } };
const tampered = obfuscateWithConfig(rawPayload, ctx);
console.log('raw:', rawPayload);
console.log('tampered:', tampered);

const res = await httpClient.request({
  method: 'GET',
  url: 'http://localhost:8099/vuln',
  params: { id: tampered },
  timeoutMs: 5000,
  retry: 0,
  ratePerSec: 100,
});
console.log('status:', res?.status);
console.log('response body:', String(res?.data ?? '').slice(0, 300));
console.log('contains SQLISCANNER0?', String(res?.data ?? '').toLowerCase().includes('sqliscanner0'));
console.log('WAF stats:', JSON.stringify(app._stats));
server.close();
process.exit(0);

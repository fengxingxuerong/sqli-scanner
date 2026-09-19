// 诊断：h2 /num 布尔通道未命中定位（multi-engine lab + CRS，方言感知 dash2hash 后）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { EngineBridgeClient, createMultiEngineApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../multi-engine-lab/lab-app.mjs')).href);

const JAVA_BIN = process.env.JAVA_BIN || 'java';
const bridge = new EngineBridgeClient(JAVA_BIN).start();
const app = createMultiEngineApp(bridge, 'h2');
const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;

const sm = new ScanManager();
const scanId = await sm.start({ url: `${base}/num?id=1`, config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false } });
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
  console.log('  evidence:', String(x.evidence || '').slice(0, 240));
}
// 报告里的点状态：确认 boolean 检测器到底跑到了哪一步
for (const p of (rep.points || [])) {
  console.log('point:', p.id, '| confirmed:', p.confirmed, '| technique:', p.technique, '| boundary:', JSON.stringify(p.boundary));
}

server.close();
bridge.stop();
process.exit(0);

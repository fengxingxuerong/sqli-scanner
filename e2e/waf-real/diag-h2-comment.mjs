// 诊断：手动拉起 multi-engine lab（h2），curl 对比 # 与 --（尾空格）两种注释形态的全链路行为
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { EngineBridgeClient, createMultiEngineApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../multi-engine-lab/lab-app.mjs')).href);

const JAVA_BIN = process.env.JAVA_BIN || 'java';
const bridge = new EngineBridgeClient(JAVA_BIN).start();
const app = createMultiEngineApp(bridge, 'h2');
const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;

// 模拟引擎投放的 URL 形态（URLSearchParams 编码：空格→+，'→%27）
function makeUrl(v) {
  const u = new URL(`${base}/num`);
  u.searchParams.set('id', v);
  return u.toString();
}

const CASES = [
  '1',
  '1 AND 1=1#',
  '1 AND 1=2#',
  '1 AND 1=1-- ',
  '1 AND 1=2-- ',
  "1' AND 1=1#",
  "1' AND 1=1-- ",
];

for (const v of CASES) {
  const url = makeUrl(v);
  const res = await fetch(url);
  const body = await res.text();
  console.log(`[${res.status}] payload=${JSON.stringify(v)}`);
  console.log(`   url=${url.slice(url.indexOf('/num'))}`);
  console.log(`   body=${body.replace(/\n/g, ' ').slice(0, 150)}`);
}

server.close();
bridge.stop();
process.exit(0);

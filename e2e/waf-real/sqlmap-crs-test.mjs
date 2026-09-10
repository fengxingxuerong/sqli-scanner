// sqlmap 对照：同一 CRS v4.1.0 WAF + 真实 MySQL 靶场
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(
  pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href
);

const MYSQL = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };
const PORT = 8160;
const BASE = `http://127.0.0.1:${PORT}`;
let hits = 0;

const pool = mysql.createPool({ ...MYSQL, connectionLimit: 8, multipleStatements: true });
const app = createMysqlLabApp(pool, (req, res, next) => {
  const v = evaluate(fromExpress(req));
  if (v.blocked) { hits++; res.status(403).send('403 CRS ' + v.ruleId); return; }
  next();
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
console.log('[sqlmap-crs] 靶场 + CRS v4.1.0 就绪');

let found = [];
try {
  const out = execFileSync('sqlmap', [
    '-u', `${BASE}/num?id=1`, '--batch', '--flush-session', '--dbms=mysql',
    '--tamper=space2comment', '--technique=BEU', '--level=3', '--risk=2', '--threads=4',
    '--output-dir', resolve(dirname(fileURLToPath(import.meta.url)), '.sqlmap-waf'),
  ], { encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  for (const line of out.split(/\r?\n/)) {
    const m = line.match(/^\s*Type:\s*(.+)$/);
    if (m) found.push(m[1].toLowerCase());
  }
} catch (e) {
  console.log('[sqlmap-crs] 执行异常:', String(e.message).slice(0, 150));
}
console.log(`[sqlmap-crs] 检出=[${found.join(',') || '-'}]  WAF 拦截 ${hits} 次`);
server.close();
await pool.end().catch(() => {});
process.exit(0);

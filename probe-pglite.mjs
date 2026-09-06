// 临时探针：验证 PGlite 在 HTTP 服务场景的关键能力（从 server 目录解析依赖）
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const _require = createRequire(new URL('./server/package.json', import.meta.url));

const { PGlite } = await import(pathToFileURL(_require.resolve('@electric-sql/pglite')).href);

const db = new PGlite();
await db.exec(
  "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT, email TEXT, password TEXT);" +
  "INSERT INTO users (name,email,password) VALUES ('alice','alice@x.com','pass123'),('bob','bob@x.com','secret456');"
);
const r = await db.query('SELECT * FROM users WHERE id=1');
console.log('rows:', JSON.stringify(r.rows));

try { await db.query('SELECT * FROM users WHERE id=1 AND 1=1'); console.log('bool ok'); }
catch (e) { console.log('bool err:', e.message); }

try { await db.query("SELECT pg_sleep(0.3)"); console.log('pg_sleep ok'); }
catch (e) { console.log('pg_sleep err:', String(e.message).slice(0, 200)); }

try { const v = await db.query('SELECT version()'); console.log('version:', JSON.stringify(v.rows)); }
catch (e) { console.log('ver err:', String(e.message).slice(0, 200)); }

// 报错文本观察：验证引擎 ERROR_SIG 能否命中真实 PG 报错
try { await db.query('SELECT * FROM users WHERE id=1 AND (SELECT 1 FROM (SELECT 1) x)'); }
catch (e) { console.log('err-subquery:', String(e.message).slice(0, 160)); }
try { await db.query('SELECT * FROM users WHERE id=1 AND extractvalue(1,concat(0x7e,(select version())))'); }
catch (e) { console.log('err-extractvalue:', String(e.message).slice(0, 160)); }
try { await db.query('SELECT * FROM users WHERE id=1 ORDER BY 3'); }
catch (e) { console.log('err-orderby:', String(e.message).slice(0, 160)); }

await db.close();
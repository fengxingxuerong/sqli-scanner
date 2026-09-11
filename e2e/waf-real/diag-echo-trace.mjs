// 诊断：/echo 误报的请求级追踪——记录引擎发出的每个请求与响应形态
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { createMysqlLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../real-mysql-lab/lab-app.js')).href);

const PORT = 8164;
const MYSQL_CONF = { host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' };
const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });

const REQLOG = [];
const crsMiddleware = (req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  const entry = { url: req.originalUrl.slice(0, 160), blocked: !!verdict.blocked, rule: verdict.ruleId || null, status: 200 };
  REQLOG.push(entry);
  if (verdict.blocked) {
    entry.status = 403;
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  // 拦截响应体记录：包装 res.send 记录回显内容
  const origSend = res.send.bind(res);
  res.send = (body) => {
    entry.respLen = String(body ?? '').length;
    entry.respExcerpt = String(body ?? '').slice(0, 180).replace(/\n/g, ' ');
    return origSend(body);
  };
  next();
};
const app = createMysqlLabApp(pool, crsMiddleware);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const scanId = await sm.start({ url: `http://127.0.0.1:${PORT}/echo?key=abc`, config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false } });
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 30));
}
const rep = sm.getReport(scanId) || {};
console.log('vulns:', (rep.vulns || []).length);
for (const x of rep.vulns || []) console.log('  payloads:', JSON.stringify(x.payloads));

// 只看 /echo 的请求（排除其它端点探测）
const echoReqs = REQLOG.filter((r) => r.url.startsWith('/echo'));
console.log(`\n/echo 请求数：${echoReqs.length}`);
// 按响应形态聚类
const groups = {};
for (const r of echoReqs) {
  const key = `${r.blocked ? 'BLOCKED(' + r.rule + ')' : 'PASS'} len=${r.respLen ?? '-'} excerpt=${(r.respExcerpt || '').slice(0, 60)}`;
  groups[key] = (groups[key] || 0) + 1;
}
console.log('响应形态分布：');
for (const [k, n] of Object.entries(groups)) console.log(`  ${n}×  ${k}`);
// 打出放行请求的完整 URL 样本（判断注入值形态）
const passUrls = [...new Set(echoReqs.filter((r) => !r.blocked).map((r) => r.url))];
console.log(`\n放行 URL 样本（前 10）：`);
passUrls.slice(0, 10).forEach((u) => console.log('  ' + u));
server.close();
await pool.end().catch(() => {});
process.exit(0);

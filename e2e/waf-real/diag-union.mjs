// ============================================================================
// e2e/waf-real/diag-union.mjs —— 定位「UNION 技术位在 CRS 下恒为 0」的断点
// 做法：在 CRS 中间件之后插桩，记录每个请求的 值/是否被拦/状态码/响应是否回显标记，
//      扫描结束后只打印 UNION 相关请求，逐段对照「无 WAF 基线」与「CRS 下」的差异。
// 用法：node e2e/waf-real/diag-union.mjs            （CRS 开启）
//       node e2e/waf-real/diag-union.mjs --nowaf    （无 WAF 基线）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const HERE = dirname(fileURLToPath(import.meta.url));
const NO_WAF = process.argv.includes('--nowaf');
const CHAIN = (process.argv.find((a) => a.startsWith('--chain=')) || '--chain=dash2hash,hexliterals').slice(8).split(',').filter(Boolean);

const { evaluate, fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const PORT = 8152;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };
{
  const probe = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 1 });
  try {
    const [r] = await probe.query('SELECT COUNT(*) c FROM users');
    console.log(`[预检] MySQL 可用，users=${r[0].c} 行`);
  } catch (e) {
    console.error(`[预检失败] ${e.message}`); process.exit(2);
  } finally { await probe.end().catch(() => {}); }
}

const LOG = [];
function makeApp() {
  const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const crsMiddleware = (req, res, next) => {
    const verdict = evaluate(fromExpress(req));
    if (verdict.blocked) {
      const all = { ...(req.query || {}), ...(req.body || {}) };
      LOG.push({ v: Object.values(all).map(String).join('|'), blocked: true, rule: verdict.ruleId, status: 403, echo: false });
      res.status(403).send('<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403</h1><p>blocked</p></body></html>');
      return;
    }
    next();
  };
  // 插桩：包住 res.send 记录状态码与响应体（只关心是否回显标记）
  const spy = (req, res, next) => {
    const orig = res.send.bind(res);
    res.send = (body) => {
      const all = { ...(req.query || {}), ...(req.body || {}) };
      const txt = String(body ?? '');
      LOG.push({
        v: Object.values(all).map(String).join('|'),
        blocked: false, rule: null, status: res.statusCode,
        echo: /SQLISCANNER\d+/.test(txt) || /__S__/.test(txt),
        len: txt.length,
      });
      return orig(body);
    };
    next();
  };
  const chain = NO_WAF ? spy : (req, res, next) => crsMiddleware(req, res, () => spy(req, res, next));
  return { app: createMysqlLabApp(pool, chain), pool };
}

const { app, pool } = makeApp();
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));

const sm = new ScanManager();
const cfg = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
if (!NO_WAF) cfg.wafEvasion = { tamper: { enabled: true, plugins: CHAIN, intensity: 'medium' } };
console.log(`[配置] WAF=${NO_WAF ? 'off' : 'CRS on'}　tamper=${CHAIN.join('+')}`);

const TARGET_URL = (process.argv.find((a) => a.startsWith('--url=')) || '--url=/num?id=1').slice(6);
const scanId = await sm.start({ url: `${BASE}${TARGET_URL}`, config: cfg });
const t0 = Date.now();
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) break;
  if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); break; }
  await new Promise((r) => setTimeout(r, 25));
}
const rep = sm.getReport(scanId) || {};
console.log(`[结果] 技术位 = [${[...new Set((rep.vulns || []).map((v) => v.technique))].join(',') || '-'}]　总请求 ${LOG.length}`);
console.log('[vulns] ' + JSON.stringify((rep.vulns || []).map((v) => ({ t: v.technique, dbms: v.dbms, ev: String(v.evidence || '').slice(0, 70) })), null, 1));
// 手工复现回显列探测，直击 discoverEchoColumnsDetailed 的判定输入
{
  const { discoverEchoColumnsDetailed } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/injection.js')).href);
  void discoverEchoColumnsDetailed;
}
const echoRows = LOG.filter((l) => /SQLISCANNER|53514c49/i.test(l.v));
console.log(`[回显探测] ${echoRows.length} 条，其中放行 ${echoRows.filter((l) => !l.blocked).length}，回显 ${echoRows.filter((l) => l.echo).length}`);

const uni = LOG.filter((l) => /union/i.test(l.v));
console.log(`\n—— UNION 相关请求 ${uni.length} 条（去重）——`);
const seen = new Set();
for (const l of uni) {
  const key = `${l.blocked ? 'B' : 'P'}${l.rule || ''}${l.echo ? 'E' : ''}${l.v.replace(/SQLISCANNER\d+/g, 'M').slice(0, 50)}`;
  if (seen.has(key)) continue;
  seen.add(key);
  console.log(`${l.blocked ? '拦' : '过'} ${String(l.rule || '-').padEnd(7)} 回显=${l.echo ? 'Y' : 'N'} len=${String(l.len ?? 0).padEnd(5)} ${l.v.slice(0, 110)}`);
}
const blockedN = uni.filter((l) => l.blocked).length;
const echoN = uni.filter((l) => !l.blocked && l.echo).length;
console.log(`[汇总] UNION 请求：被拦 ${blockedN}，放行 ${uni.length - blockedN}，回显成功 ${echoN}`);

// ORDER BY 猜列数（UnionDetector 判定链的第一步，被拦则 union 直接不出结果）
const ob = LOG.filter((l) => /order\s+by/i.test(l.v));
console.log(`\n—— ORDER BY 猜列数请求 ${ob.length} 条 ——`);
for (const l of ob.slice(0, 40)) {
  console.log(`${l.blocked ? '拦' : '过'} ${String(l.rule || '-').padEnd(7)} ${l.v.slice(0, 90)}`);
}
console.log(`[汇总] ORDER BY：被拦 ${ob.filter((l) => l.blocked).length} / ${ob.length}`);

// 门控探针：_gateInjection 发 `AND 1=1` / `AND 1=2`（tamper 开时尾注为 /*）
const gate = LOG.filter((l) => /AND\s+1=[12]/.test(l.v));
console.log(`\n—— 门控探针（AND 1=1 / AND 1=2）${gate.length} 条 ——`);
for (const l of gate) {
  console.log(`${l.blocked ? '拦' : '过'} ${String(l.rule || '-').padEnd(7)} status=${l.status} len=${l.len ?? 0}  ${l.v.slice(0, 80)}`);
}

// 前 25 条请求的时序（定位门控 _gateInjection 是否被拦）
console.log('\n—— 前 25 条请求时序 ——');
for (const l of LOG.slice(0, 25)) {
  console.log(`${l.blocked ? '拦' : '过'} ${String(l.rule || '-').padEnd(7)} ${l.v.slice(0, 90)}`);
}
server.close();
await pool.end().catch(() => {});
process.exit(0);

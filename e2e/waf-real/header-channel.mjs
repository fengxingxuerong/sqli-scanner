// ============================================================================
// e2e/waf-real/header-channel.mjs —— 请求头通道（header 注入点）端到端验证
//
// 背景：CRS 942 系有大量规则只覆盖 ARGS|ARGS_NAMES|REQUEST_COOKIES|XML:/*，
// 自定义请求头不在其检测面内 → 请求头是天然的「通道绕过」面。
//
// 引擎侧能力（TargetParser level>=3 生成 header 注入点 + buildInjectionRequest 支持
// location==='header'）已存在，但**默认 level=1 根本不生成**，等于能力闲置。
//
// 本脚本验证三件事：
//   ① 目标确实把自定义头拼进 SQL（通道成立）
//   ② CRS 对 header 通道的拦截率显著低于 URL 通道（确认「通道绕过」成立）
//   ③ level=1 不检出 / level>=3 检出（确认默认配置下该通道是盲区）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const express = require('express');
const HERE = dirname(fileURLToPath(import.meta.url));
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const PORT = 8154;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };
const HEADER_NAME = 'X-User-Id';

// [预检] 靶场没起 → 引擎必然 0 检出，会得出假结论
{
  const probe = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 1 });
  try {
    const [rows] = await probe.query('SELECT COUNT(*) c FROM users');
    console.log(`[预检] MySQL 可用，users=${rows[0].c} 行`);
  } catch (e) {
    console.error(`[预检失败] ${e.message}\n请先启动：/d/mysql/bin/mysqld --datadir=D:/mysql/data --port=3307`);
    process.exit(2);
  } finally {
    await probe.end().catch(() => {});
  }
}

let BLOCKS = []; // { where, value, ruleId }

// 两个等价的注入点：一个走 URL 参数，一个走自定义请求头，SQL 完全相同
function makeApp() {
  const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const app = express();

  const crsGuard = (where) => (req, res, next) => {
    const verdict = evaluate(fromExpress(req));
    if (verdict.blocked) {
      BLOCKS.push({ where, value: String(req.headers[HEADER_NAME.toLowerCase()] ?? req.query.id ?? '').slice(0, 120), ruleId: verdict.ruleId });
      res.status(403).send('<!DOCTYPE html><html><head><title>403</title></head><body><h1>403</h1><p>blocked</p></body></html>');
      return;
    }
    next();
  };

  const render = (rows) => `<!DOCTYPE html><html><body><h1>Profile</h1><table>${
    (rows || []).map((r) => `<tr>${Object.values(r).map((v) => `<td>${String(v)}</td>`).join('')}</tr>`).join('')
  }</table></body></html>`;

  // URL 通道（对照组）
  app.get('/by-url', crsGuard('url'), async (req, res) => {
    try {
      const [rows] = await pool.query(`SELECT * FROM users WHERE id = ${req.query.id || '1'}`);
      res.send(render(rows));
    } catch (e) {
      res.status(500).send(`<!DOCTYPE html><body>ERR ${String(e.message).slice(0, 160)}</body>`);
    }
  });

  // Header 通道（实验组）：同一个 SQL，只是值来自自定义请求头
  app.get('/by-header', crsGuard('header'), async (req, res) => {
    try {
      const [rows] = await pool.query(`SELECT * FROM users WHERE id = ${req.headers[HEADER_NAME.toLowerCase()] || '1'}`);
      res.send(render(rows));
    } catch (e) {
      res.status(500).send(`<!DOCTYPE html><body>ERR ${String(e.message).slice(0, 160)}</body>`);
    }
  });

  return { app, pool };
}

async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); return []; }
    await new Promise((r) => setTimeout(r, 25));
  }
  return (sm.getReport(scanId) || {}).vulns || [];
}

async function scenario({ label, url, level, headerParams }) {
  BLOCKS = [];
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  // 注意：headerParams 属于 **target 顶层**（与 bodyParams/cookieParams 同级），
  // 不是 config 的子字段——scanRoutes.sanitizeStart 就是这么组装 target 的。
  const vulns = await runScan(sm, {
    url: `${BASE}${url}`,
    config: {
      concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000,
      enableExtract: false, level,
    },
    headerParams: headerParams || {},
  });
  await new Promise((r) => server.close(r));
  await pool.end().catch(() => {});
  await new Promise((r) => setTimeout(r, 150));

  const techs = [...new Set(vulns.map((v) => v.technique))];
  const byWhere = {};
  for (const b of BLOCKS) byWhere[b.where] = (byWhere[b.where] || 0) + 1;
  console.log(`\n[${label}] level=${level}　检出=[${techs.join(',') || '-'}]`);
  console.log(`   被拦请求 ${BLOCKS.length}（url ${byWhere.url || 0} / header ${byWhere.header || 0}）`);
  return { techs, blocked: BLOCKS.length, byWhere };
}

console.log('===== ① 通道成立性：header 值是否真的进了 SQL =====');
{
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const mk = (h) => fetch(`${BASE}/by-header`, { headers: { [HEADER_NAME]: h } }).then((r) => r.text());
  const ok = await mk('1');
  const inject = await mk('1 AND 1=1');
  const injectFalse = await mk('1 AND 1=2');
  console.log(`   正常值行数=${(ok.match(/<tr>/g) || []).length}　AND 1=1 行数=${(inject.match(/<tr>/g) || []).length}　AND 1=2 行数=${(injectFalse.match(/<tr>/g) || []).length}`);
  console.log(`   → 布尔分化 ${(inject.match(/<tr>/g) || []).length !== (injectFalse.match(/<tr>/g) || []).length ? '成立（通道有效）' : '不成立（靶场有问题）'}`);
  await new Promise((r) => server.close(r));
  await pool.end().catch(() => {});
  await new Promise((r) => setTimeout(r, 150));
}

console.log('\n===== ② 检出能力：level=1（默认）vs level>=3 =====');
const r1 = await scenario({ label: 'URL 通道  ', url: '/by-url?id=1', level: 1, headerParams: { [HEADER_NAME]: '1' } });
const r2 = await scenario({ label: 'Header 通道', url: '/by-header', level: 1, headerParams: { [HEADER_NAME]: '1' } });
const r3 = await scenario({ label: 'Header 通道', url: '/by-header', level: 3, headerParams: { [HEADER_NAME]: '1' } });
const r4 = await scenario({ label: 'Header 通道', url: '/by-header', level: 4, headerParams: { [HEADER_NAME]: '1' } });

console.log('\n===== 结论 =====');
console.log(`默认 level=1 下：URL 通道检出 [${r1.techs.join(',') || '-'}]，header 通道检出 [${r2.techs.join(',') || '-'}]`);
console.log(`level=3：header 通道检出 [${r3.techs.join(',') || '-'}]`);
console.log(`level=4：header 通道检出 [${r4.techs.join(',') || '-'}]`);
process.exit(0);

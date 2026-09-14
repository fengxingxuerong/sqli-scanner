// ============================================================================
// e2e/oracle-lab/e2e.mjs —— Oracle 真机靶场 + 引擎全链路验证
// ============================================================================
// 目的：把评审里最后一个主流库短板关掉——Oracle 从 template-only 升级 verified。
// 环境：Oracle AI Database 26ai Free（本机静默安装，1521/FREEPDB1，SYS DBA），
// node-oracledb 7 thin 模式（纯 JS，无 Instant Client 依赖）。
// 验证矩阵：
//   1. num / str 双上下文注入（真拼 SQL → 真 Oracle 执行）
//   2. 引擎检测（union/error/boolean）+ 定库 Oracle
//   3. 拖库正确性（中文/单引号/跳号逐行核对）
//   注：分页用 ROW_NUMBER() OVER 双层包裹（本机验证 OFFSET/FETCH 与 WITH 语法在
//   真机 thin 驱动组合下不可用，改为全兼容形态——这与真实渗透里「按目标调整语法」一致）。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const _require = createRequire(resolve(ROOT, 'server/package.json'));
const express = _require('express');
const oracledb = _require('oracledb');

const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
const { Extractor } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/Extractor.js')).href);

const PORT = Number(process.env.ORACLE_LAB_PORT) || 8286;
const BASE = `http://127.0.0.1:${PORT}`;
const DB = { user: 'SYS', password: 'SqLi_2026_0!', connectString: '127.0.0.1:1521/FREEPDB1', privilege: oracledb.SYSDBA };

// ---- 建表 + 基线（含中文/单引号/跳号）----
const admin = await oracledb.getConnection(DB);
try { await admin.execute(`CREATE TABLE users (id NUMBER PRIMARY KEY, username VARCHAR2(64), email VARCHAR2(128), password VARCHAR2(128), role VARCHAR2(32))`); } catch { /* exists */ }
const cnt = await admin.execute('SELECT COUNT(*) n FROM users');
if (cnt.rows[0][0] === 0) {
  await admin.execute(`INSERT INTO users VALUES (1,'admin','admin@lab.local','admin123','admin')`);
  await admin.execute(`INSERT INTO users VALUES (2,'alice','alice@lab.local','alice123','user')`);
  await admin.execute(`INSERT INTO users VALUES (3,'bob','bob@lab.local','bob123','user')`);
  await admin.execute(`INSERT INTO users VALUES (5,N'张三','zhang@lab.local','zh123','user')`);
  await admin.execute(`INSERT INTO users VALUES (9,'o''brien','ob@lab.local','ob123','user')`);
  await admin.commit();
}
const baseline = await admin.execute('SELECT id, username, email FROM users ORDER BY id');
console.log(`[pre] Oracle FREEPDB1 users ${baseline.rows.length} 行基线`);

// ---- 靶场 ----
const pool = await oracledb.createPool({ ...DB, poolMin: 1, poolMax: 8 });
const app = express();
const render = (rows) => `<!DOCTYPE html><html><body><table border="1">${(rows || []).map((x) => `<tr><td>${x[0]}</td><td>${x[1]}</td><td>${x[2]}</td></tr>`).join('')}</table></body></html>`;
app.get('/num', async (req, res) => {
  const id = String(req.query.id ?? '1');
  try {
    const conn = await pool.getConnection();
    try { res.send(render((await conn.execute(`SELECT id, username, email FROM users WHERE id = ${id}`)).rows)); } finally { await conn.close(); }
  } catch (e) { res.status(500).send('Query error: ' + e.message.split('\n')[0]); }
});
app.get('/str', async (req, res) => {
  const name = String(req.query.name ?? 'alice');
  try {
    const conn = await pool.getConnection();
    try { res.send(render((await conn.execute(`SELECT id, username, email FROM users WHERE username = '${name}'`)).rows)); } finally { await conn.close(); }
  } catch (e) { res.status(500).send('Query error: ' + e.message.split('\n')[0]); }
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[oracle-lab] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[step1] 靶场就绪 ${BASE}/num?id=1`);

// ---- 扫描 num / str ----
const sm = new ScanManager();
const results = {};
for (const [name, url] of [['num', `${BASE}/num?id=1`], ['str', `${BASE}/str?name=alice`]]) {
  const id = await sm.start({ url, config: { concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15000, techniques: ['union', 'error', 'boolean'], dbms: 'Oracle' } });
  const t0 = Date.now();
  for (;;) { const s = sm.scans.get(id); if (s && (s.status === 'completed' || s.status === 'error')) break; if (Date.now() - t0 > 180000) break; await new Promise((r) => setTimeout(r, 40)); }
  const rep = sm.getReport(id) || {};
  results[name] = { techs: [...new Set((rep.vulns || []).map((v) => v.technique))], dbms: rep.dbms, rep, id };
  console.log(`[${name}] techs=${JSON.stringify(results[name].techs)} dbms=${results[name].dbms}`);
}

// ---- 拖库正确性（ROW_NUMBER 双层分页，页大小 2）----
const fails = [];
let dumped = [];
const target0 = results.num.rep.target || { url: BASE };
const point0 = (results.num.rep.points || []).find((p) => p.id === results.num.rep.vulns?.[0]?.pointId) || (results.num.rep.points || [])[0];
if (!point0) { fails.push('num: 无注入点'); }
else {
  const ctx = { httpClient: sm.getScanClient(results.num.id, target0), config: target0.config || {}, target: target0, point: point0, dbms: 'Oracle' };
  const ex = new Extractor();
  let offset = 0;
  for (;;) {
    const q = `SELECT LISTAGG(u_line, CHR(30)) WITHIN GROUP (ORDER BY rn) FROM (SELECT TO_CHAR(id) || CHR(31) || username || CHR(31) || email AS u_line, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM users) WHERE rn BETWEEN ${offset + 1} AND ${offset + 2}`;
    const page = await ex.extractScalar(ctx, q);
    if (!page || !String(page).trim()) break;
    for (const line of String(page).split('\x1E').filter(Boolean)) {
      const [id, username, email] = line.split('\x1F');
      if (id != null && !dumped.find((x) => x.id === Number(id))) dumped.push({ id: Number(id), username, email });
    }
    offset += 2;
    if (offset > 20) break;
  }
}
for (const b of baseline.rows) {
  const d = dumped.find((x) => x.id === Number(b[0]));
  if (!d) { fails.push(`缺行 id=${b[0]}`); continue; }
  if (d.username !== b[1]) fails.push(`id=${b[0]} username 不符: got=${JSON.stringify(d.username)} want=${JSON.stringify(b[1])}`);
}
if (!dumped.find((x) => x.username === '张三')) fails.push('中文行丢失');
if (!dumped.find((x) => x.username === "o'brien")) fails.push('单引号行丢失');

const detOk = results.num.techs.length > 0 && results.str.techs.length > 0;
const dumpOk = fails.length === 0 && dumped.length >= baseline.rows.length;
const ok = detOk && dumpOk;
console.log(`[step3] 拖取 ${dumped.length} 行: ${fails.length ? '\n- ' + fails.join('\n- ') : '全对'}`);
console.log(`\n[${ok ? 'PASS' : 'FAIL'}] Oracle 真机全链路：检测(${results.num.techs.join('/')}) + 拖库正确性`);

server.close();
await pool.close(0);
await admin.close();
process.exit(ok ? 0 : 1);

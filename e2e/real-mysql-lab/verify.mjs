// ============================================================================
// e2e/real-mysql-lab/verify.mjs —— 真实 MySQL 8.0.28 驱动靶场验证
// 用法：node e2e/real-mysql-lab/verify.mjs [--sqlmap]
// 环境变量：MYSQL_LAB_PORT(8140) / MYSQL_HOST / MYSQL_PORT(3306) / MYSQL_USER / MYSQL_PASSWORD / MYSQL_DATABASE
// 流程：init 自检 → 起 lab-app（mysql2 直连）→ 逐端点引擎扫描 → 可选 sqlmap 对拍 → 报告
// ============================================================================
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from './lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
import { pathToFileURL } from 'node:url';
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.MYSQL_LAB_PORT) || 8140;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  // 密码允许空串（本机 root 常为空密码），用 ?? 而非 ||
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};

const SCENARIOS = [
  { name: 'num', desc: '数值型（union/error/boolean/time 全通道）', target: () => ({ url: `${BASE}/num?id=1` }), must: ['union'], nice: ['error', 'boolean', 'time'] },
  { name: 'str', desc: "字符串型（' 闭合）", target: () => ({ url: `${BASE}/str?name=alice` }), must: ['boolean'], nice: ['union', 'error'] },
  { name: 'like', desc: 'LIKE 上下文（%\' 闭合，P1-3 修复验证）', target: () => ({ url: `${BASE}/like?q=keyboard` }), must: ['boolean'], nice: ['error', 'union'] },
  { name: 'orderby', desc: 'ORDER BY 位置注入（子句轮需 level≥2）', target: () => ({ url: `${BASE}/orderby?sort=id` }), must: ['boolean'], nice: [], cfg: { level: 2 } },
  { name: 'blind', desc: '布尔盲注（错误吞掉，无回显）', target: () => ({ url: `${BASE}/blind?uid=1` }), must: ['boolean'], nice: [] },
  // ⚠️ [FLAKY 2026-09-23 实测] 本场景在 CI（ubuntu + MySQL 8.0.46 容器）上**间歇失败**：
  //   同一份代码，16:34 那轮 `检出=[time] miss=[boolean]`（FAIL，耗时 6345ms），
  //   16:50 原地 rerun 同一 job → PASS=10/FAIL=0。即 `/noisy` 的 boolean 判定会随
  //   **宿主负载/时序**抖动（强动态页本就靠差异稳定性判布尔，是最脆的一类）。
  //   ⛔ 不要把它降级成 nice 了事 —— 那会让门禁对这块永远失明。正确处置是**修布尔判定的
  //   抗噪性**（噪声页的采样数/阈值/去噪），并把本注释连同复跑证据一起删掉。
  //   现状（如实）：门禁含 1 个已知 flaky 项，红灯出现时**先 rerun 再看**是否是它。
  { name: 'noisy', desc: '强动态页布尔盲注（todo#38：高密度动态内容 + 注入）', target: () => ({ url: `${BASE}/noisy?uid=1` }), must: ['boolean'], nice: [] },
  { name: 'time', desc: '时间盲注（内容恒定）', target: () => ({ url: `${BASE}/time?tid=1` }), must: ['time'], nice: [] },
  // stacked/inline 为 opt-in 技术（默认 techniques 不含），需显式指定
  { name: 'stacked', desc: '堆叠注入（opt-in 技术）', target: () => ({ url: `${BASE}/stacked?i=1` }), must: ['stacked'], nice: [], cfg: { techniques: ['stacked'] } },
  { name: 'safe', desc: '参数化占位符（期望 0 检出）', target: () => ({ url: `${BASE}/safe?id=1` }), must: [], nice: [], expectSafe: true },
  { name: 'echo', desc: '输入不进 SQL（期望 0 检出）', target: () => ({ url: `${BASE}/echo?key=abc` }), must: [], nice: [], expectSafe: true },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };

async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [], elapsedMs: Date.now() - t0 }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [], elapsedMs: Date.now() - t0 };
}

const techs = (vulns) => [...new Set((vulns || []).map((v) => v.technique))];

function runSqlmap(url) {
  const t0 = Date.now();
  try {
    const out = execFileSync('sqlmap', [
      '-u', url, '--batch', '--flush-session', '--dbms=mysql',
      '--technique=BEUSTQ', '--time-sec=2', '--level=3', '--risk=2', '--threads=4',
      '--output-dir', resolve(HERE, '.sqlmap-out'),
    ], { encoding: 'utf8', timeout: 300000, windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
    const found = new Set();
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(/^\s*Type:\s*(.+)$/);
      if (!m) continue;
      const l = m[1].toLowerCase();
      if (l.includes('boolean')) found.add('boolean');
      else if (l.includes('error')) found.add('error');
      else if (l.includes('union')) found.add('union');
      else if (l.includes('stacked')) found.add('stacked');
      else if (l.includes('time-based')) found.add('time');
      else if (l.includes('inline')) found.add('inline');
    }
    return { found: [...found], elapsedMs: Date.now() - t0, err: null };
  } catch (e) {
    return { found: [], elapsedMs: Date.now() - t0, err: String(e.message).slice(0, 200) };
  }
}

// —— main ——
// 连接自检
{
  const c = await mysql.createConnection(MYSQL_CONF);
  const [v] = await c.query('SELECT VERSION() v');
  console.log(`[verify] MySQL ${v[0].v} @ ${MYSQL_CONF.host}:${MYSQL_CONF.port}/${MYSQL_CONF.database}`);
  await c.end();
}

const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
const app = createMysqlLabApp(pool);
const server = app.listen(PORT, '127.0.0.1');
// [P0-FIX 2026-09-14] listen 失败硬退出（对齐 pentest-lab 守卫）：端口被占时静默扫错目标 = 废报告还 exit 0
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', (e) => reject(new Error('[real-mysql-lab] 靶场端口监听失败（被占用？先杀残留进程）: ' + e.message)));
});
console.log(`[verify] 靶场就绪 ${BASE}  sqlmap对拍=${process.argv.includes('--sqlmap') ? 'on' : 'off'}\n`);

const sm = new ScanManager();
const rows = [];
let pass = 0;
for (const sc of SCENARIOS) {
  const out = await runScan(sm, { ...sc.target(), config: { ...baseConfig, ...(sc.cfg || {}) } });
  const found = techs(out.vulns);
  const dbms = [...new Set((out.vulns || []).map((v) => v.dbms).filter(Boolean))];
  const miss = sc.must.filter((t) => !found.includes(t));
  const ok = out.status === 'completed' && miss.length === 0 && (sc.expectSafe ? found.length === 0 : true);
  if (ok) pass++;
  rows.push({ name: sc.name, desc: sc.desc, found, dbms, must: sc.must, miss, elapsedMs: out.elapsedMs, status: out.status, ok, expectSafe: !!sc.expectSafe });
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${sc.name.padEnd(9)} 检出=[${found.join(',') || '-'}]  dbms=${dbms.join(',') || '?'}  耗时=${out.elapsedMs}ms${miss.length ? '  miss=[' + miss.join(',') + ']' : ''}`);
}

// sqlmap 对拍（数值型代表场景）
let sqlmapRow = null;
if (process.argv.includes('--sqlmap')) {
  console.log('\n[verify] sqlmap 对拍 /num?id=1（--dbms=mysql）…');
  const sq = runSqlmap(`${BASE}/num?id=1`);
  sqlmapRow = { name: 'sqlmap_num', found: sq.found, elapsedMs: sq.elapsedMs, err: sq.err };
  console.log(`[sqlmap] 检出=[${sq.found.join(',') || '-'}] 耗时=${sq.elapsedMs}ms${sq.err ? ` err=${sq.err}` : ''}`);
  const ours = rows.find((r) => r.name === 'num');
  console.log(`[对比] 引擎=${ours.found.join(',')} (${ours.elapsedMs}ms) vs sqlmap=${sq.found.join(',') || '-'} (${sq.elapsedMs}ms)`);
}

server.close();
await pool.end().catch(() => {});

mkdirSync(RESULTS_DIR, { recursive: true });
writeFileSync(
  resolve(RESULTS_DIR, 'real-mysql-report.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), mysql: `${MYSQL_CONF.host}:${MYSQL_CONF.port}/${MYSQL_CONF.database}`, pass, total: SCENARIOS.length, rows, sqlmap: sqlmapRow }, null, 2),
);
console.log(`\n[verify] ${pass}/${SCENARIOS.length} PASS → ${resolve(RESULTS_DIR, 'real-mysql-report.json')}`);
process.exit(pass === SCENARIOS.length ? 0 : 1);

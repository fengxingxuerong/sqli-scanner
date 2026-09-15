// ============================================================================
// blackbox-lab / sqlmap-bench.mjs —— sqlmap 同题对照
//
// 为什么必需：没有权威工具对照，就无法区分「本工具的缺陷」与「这类靶点本来就难判」。
// 取与 run-scan.mjs 完全相同的靶点，跑 sqlmap，记录命中/技术位/DBMS。
//
// 坑（本机实测）：
//   1. 环境变量里有 http_proxy/https_proxy 时，sqlmap 会读它并与 --ignore-proxy 互斥直接退出
//      → spawn 前把所有 *_proxy 变量删掉。
//   2. 批量连跑偶尔 2s 快速退出 → 造成「假 miss」，需重跑一次并核对日志。
//   3. sqlmap 是 Windows exe（Python39 的 Scripts 下），路径含中文需用数组参数传递。
//
// 用法：node e2e/blackbox-lab/sqlmap-bench.mjs [--only=id1,id2]
// ============================================================================

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = Number(process.env.LAB_PORT || 8099);
const BASE = `http://127.0.0.1:${PORT}`;
const OUT = path.join(HERE, 'out');
fs.mkdirSync(OUT, { recursive: true });

const SQLMAP =
  process.env.SQLMAP_PATH ||
  'C:/Users/Admin（无密码）/AppData/Local/Programs/Python/Python39/Scripts/sqlmap.exe';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startLab() {
  const proc = spawn('node', [path.join(HERE, 'lab-app.mjs')], {
    cwd: ROOT,
    env: { ...process.env, LAB_PORT: String(PORT), LAB_WAF: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  proc.stdout.on('data', (d) => { log += d; });
  proc.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/__lab/health`);
      if (r.ok) return { proc, log: () => log };
    } catch { /* 未就绪 */ }
    await sleep(250);
  }
  try { proc.kill(); } catch { /* noop */ }
  throw new Error('靶场启动失败:\n' + log.slice(0, 600));
}

// 与 run-scan.mjs 相同的靶点集合（保证同题）
const POINTS = [
  { id: 'A1-numeric', url: '/api/user?id=1' },
  { id: 'A2-string', url: '/api/search?name=alice' },
  { id: 'A3-like', url: '/api/like?q=Keyboard' },
  { id: 'A4-orderby', url: '/api/sort?by=price' },
  { id: 'B1-error', url: '/api/product?id=1' },
  { id: 'C1-blindbool', url: '/api/blind?id=1' },
  { id: 'C2-blindtime', url: '/api/sleep?id=1', timeoutMs: 300000 },
  { id: 'D2-json', url: '/api/order', extra: ['--method=POST', '--data=item=USB-C Hub'] },
  { id: 'D3-cookie', url: '/api/profile', extra: ['--cookie=uid=1', '--level=2'] },
  { id: 'D4-xff', url: '/api/visitor', extra: ['--headers=X-Forwarded-For: alice', '--level=2'] },
  { id: 'D5-base64', url: '/api/encoded?d=MQ%3D%3D' },
  { id: 'D6-pathseg', url: '/api/rest/1' },
  { id: 'E2-stacked', url: '/api/batch?id=1' },
  { id: 'F1-parametrized', kind: 'safe', url: '/api/safe/user?id=1' },
  { id: 'F2-nonce', kind: 'safe', url: '/api/safe/nonce' },
  { id: 'F3-const500', kind: 'safe', url: '/api/safe/error' },
  { id: 'F4-const403', kind: 'safe', url: '/api/safe/forbidden' },
  { id: 'F5-redirect', kind: 'safe', url: '/api/safe/redirect' },
  { id: 'F6-static', kind: 'safe', url: '/static/hello.html' },
  { id: 'F7-intval', kind: 'safe', url: '/api/safe/intval?id=1' },
];

function cleanEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (/_proxy$/i.test(k)) delete env[k];   // 坑 1：与 --ignore-proxy 互斥
  }
  return env;
}

function runSqlmap(point, logFile, attempt) {
  const args = [
    '--batch', '--flush-session', '--ignore-proxy',
    '-u', BASE + point.url,
    '--level=1', '--risk=1',
    ...(point.extra || []),
    ...(attempt > 0 ? ['--smart'] : []),
  ];
  return new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn(SQLMAP, args, { cwd: ROOT, env: cleanEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => { try { p.kill(); } catch { /* noop */ } }, point.timeoutMs || 240000);
    p.on('exit', (code) => {
      clearTimeout(timer);
      try { fs.writeFileSync(logFile, out, 'utf8'); } catch { /* noop */ }
      resolve({ code, ms: Date.now() - t0, log: out });
    });
  });
}

function parseSqlmap(log) {
  const lower = log.toLowerCase();
  // 必须先排除否定句式：sqlmap 的 "does not seem to be injectable" /
  // "all tested parameters do not appear to be injectable" 都含 "injectable"，
  // 首版正则只匹配 "injectable" 就把**未检出**的点误判成命中（F3 就中招了）。
  // 教训：判定脚本本身也是被测代码，要先拿已知点验证过再用。
  const neg = /not injectable|does not seem to be injectable|do not appear to be injectable|all tested parameters do not appear/i;
  const pos = /is vulnerable|appears? to be injectable|is injectable|parameter ['"][^'"]+['"] is vulnerable/i;
  const vuln = pos.test(log) && !neg.test(log);
  const techniques = [];
  for (const t of ['boolean-based blind', 'error-based', 'UNION query', 'stacked queries', 'time-based blind', 'inline query']) {
    if (lower.includes(t.toLowerCase())) techniques.push(t);
  }
  let dbms = null;
  const m = /back-end DBMS(?: is|:\s)?\s*([a-z0-9_ ]+)/i.exec(log);
  if (m) dbms = m[1].trim().split(/[\n\r]/)[0].slice(0, 30);
  return { vuln, techniques, dbms };
}

async function main() {
  const argv = process.argv.slice(2);
  const onlyArg = argv.find((a) => a.startsWith('--only='));
  const only = onlyArg ? onlyArg.split('=')[1].split(',').map((s) => s.trim()) : null;
  const targets = only ? POINTS.filter((p) => only.includes(p.id)) : POINTS;

  const { proc } = await startLab();
  console.log(`[sqlmap-bench] 靶场已起 ${BASE}  点=${targets.length}`);
  console.log(`[sqlmap-bench] sqlmap=${SQLMAP}`);

  const rows = [];
  for (const point of targets) {
    const logFile = path.join(OUT, `${point.id}.sqlmap.log`);
    let r = await runSqlmap(point, logFile, 0);
    // 坑 2：2s 内快速退出基本是异常，重跑一次
    if (r.ms < 2500) {
      r = await runSqlmap(point, logFile, 1);
    }
    const v = parseSqlmap(r.log);
    const row = {
      id: point.id, kind: point.kind || 'vuln',
      hit: v.vuln, techniques: v.techniques, dbms: v.dbms,
      ms: r.ms, exitCode: r.code,
    };
    rows.push(row);
    const mark = row.kind === 'safe' ? (row.hit ? 'FALSE-POSITIVE' : 'clean') : (row.hit ? 'HIT' : 'MISS');
    console.log(`  ${point.id.padEnd(16)} ${mark.padEnd(15)} ${(row.ms / 1000).toFixed(1)}s` +
      `  tech=[${v.techniques.join(',')}]  dbms=${v.dbms}`);
  }

  fs.writeFileSync(path.join(OUT, 'sqlmap-matrix.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), tool: 'sqlmap', rows }, null, 2), 'utf8');

  const vuln = rows.filter((r) => r.kind === 'vuln');
  const safe = rows.filter((r) => r.kind === 'safe');
  console.log('\n=== sqlmap 汇总 ===');
  console.log(`  漏洞检出 ${vuln.filter((r) => r.hit).length}/${vuln.length}` +
    `  安全误报 ${safe.filter((r) => r.hit).length}/${safe.length}`);
  const miss = vuln.filter((r) => !r.hit);
  if (miss.length) console.log(`  漏报: ${miss.map((r) => r.id).join(',')}`);
  const fp = safe.filter((r) => r.hit);
  if (fp.length) console.log(`  误报: ${fp.map((r) => r.id).join(',')}`);

  try { proc.kill(); } catch { /* noop */ }
  console.log('\n[sqlmap-bench] 靶场已停止');
}

main().catch((e) => { console.error('[sqlmap-bench] 失败:', e.message); process.exit(2); });

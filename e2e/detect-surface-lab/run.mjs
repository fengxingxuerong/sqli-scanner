// 检测面探针跑批（D154）
//
// 逐条跑 CLI（一键扫描形态），读 report.json 判「这条载体到底测没测到」。
// 判据刻意只有两种结果，不做加权：
//   · vuln 用例：必须检出，漏检 ⇒ exit 1（漏检就是本靶场存在的理由）
//   · safe 用例：必须 0 检出，误报 ⇒ exit 1
//
// 用法：node e2e/detect-surface-lab/run.mjs [--only=id1,id2] [--keep]
// 前置：MySQL 3306 可用（root/root 或 LAB_DB_PASSWORD）；无库 ⇒ exit 2（BLOCKED，不冒充结论）
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = Number(process.env.DS_LAB_PORT || 8234);
const BASE = `http://127.0.0.1:${PORT}`;
const RESULTS = path.join(HERE, 'results');

const CASES = [
  // 多段路径：id 在中间段
  { id: 'multi-seg', path: '/api/users/1/orders', vuln: true, carrier: '多段路径中间段' },
  { id: 'multi-seg-safe', path: '/safe/users/1/orders', vuln: false, carrier: '多段路径（安全对照）' },
  // .json 后缀段
  { id: 'json-suffix', path: '/api/item/1.json', vuln: true, carrier: '.json 后缀段' },
  { id: 'json-suffix-safe', path: '/safe/item/1.json', vuln: false, carrier: '.json 后缀（安全对照）' },
  // 矩阵参数
  { id: 'matrix', path: '/api/matrix;cat=1', vuln: true, carrier: '矩阵参数 ;cat=' },
  { id: 'matrix-safe', path: '/safe/matrix;cat=1', vuln: false, carrier: '矩阵参数（安全对照）' },
  // 重复 query 键
  { id: 'dup-key', path: '/dup?a=1&a=2', vuln: true, carrier: '重复 query 键' },
  { id: 'dup-key-safe', path: '/safe/dup?a=1&a=2', vuln: false, carrier: '重复键（安全对照）' },
  // 基准对照：普通单值 query（应稳定检出，用来证明靶场/链路本身没问题）
  { id: 'plain-query', path: '/dup?a=1', vuln: true, carrier: '普通 query（基准）' },
  { id: 'plain-query-safe', path: '/safe/dup?a=1', vuln: false, carrier: '普通 query（安全对照）' },
];

/**
 * 解析 --only=a,b
 * @param {string[]} argv
 * @returns {Set<string>|null}
 */
function parseOnly(argv) {
  const hit = argv.find((a) => a.startsWith('--only='));
  if (!hit) return null;
  return new Set(hit.slice('--only='.length).split(',').filter(Boolean));
}

/**
 * 等端口起来（最多 15s）
 * @returns {Promise<void>}
 */
async function waitReady() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch { /* 还没起来 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('靶场 15s 内没起来');
}

/**
 * 跑一条用例，返回 {hit, vulnCount, verdict, ms}
 * @param {{id:string,path:string,vuln:boolean}} c
 * @returns {{hit:boolean, vulns:number, verdict:string, ms:number}}
 */
function scanCase(c) {
  const outDir = path.join(RESULTS, c.id);
  fs.rmSync(outDir, { recursive: true, force: true });
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts/one-click-scan.mjs'),
    '-u', BASE + c.path,
    '--level', '3', '--test-path',
    '--technique', 'union,error,boolean',
    '--formats', 'json',
    '-o', outDir,
    '--no-ledger', '--quiet',
    '--retries', '1', '--http-timeout', '8000', '--timeout', '120000',
  ], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, SSRF_ALLOW_PRIVATE: '1', NO_PROXY: '127.0.0.1,localhost' },
  });
  const ms = Date.now() - t0;
  const reportPath = path.join(outDir, 'report.json');
  let vulns = 0;
  let verdict = 'no-report';
  if (fs.existsSync(reportPath)) {
    const j = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    vulns = Array.isArray(j.vulns) ? j.vulns.length : 0;
    verdict = j.summary?.verdict || 'unknown';
  }
  // exit 2 = 发现 High/Critical；以报告为准，exit 只做兜底
  return { hit: vulns > 0 || r.status === 2, vulns, verdict, ms, exit: r.status, tail: (r.stderr || '').slice(-400) };
}

/**
 * 靶场是否还活着
 * @returns {Promise<boolean>}
 */
async function alive() {
  try {
    const r = await fetch(`${BASE}/healthz`);
    return r.ok;
  } catch {
    return false;
  }
}

const only = parseOnly(process.argv.slice(2));
const cases = only ? CASES.filter((c) => only.has(c.id)) : CASES;
if (!cases.length) {
  console.error('--only 没匹配到任何用例');
  process.exit(2);
}

fs.mkdirSync(RESULTS, { recursive: true });
const child = spawn(process.execPath, [path.join(HERE, 'server.mjs')], {
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env },
});
let serverLog = '';
child.stdout.on('data', (d) => { serverLog += d.toString(); });
child.stderr.on('data', (d) => { serverLog += d.toString(); });

let exitCode = 0;
try {
  await waitReady();
  console.log('═══ 检测面探针（D154）═══');
  const rows = [];
  for (const c of cases) {
    // 每条用例前先探活：靶场挂掉必须 BLOCKED，不能把「靶场没了」记成「引擎漏检」
    if (!(await alive())) {
      console.error(`BLOCKED: 扫描 ${c.id} 前靶场已不可达（见 results/server.log）`);
      exitCode = 2;
      break;
    }
    const r = scanCase(c);
    const ok = c.vuln ? r.hit : !r.hit;
    if (!ok) exitCode = 1;
    rows.push({ ...c, ...r, ok });
    console.log(
      `${ok ? '✅' : '❌'} ${c.id.padEnd(16)} ${c.carrier.padEnd(22)} 检出=${r.vulns} verdict=${r.verdict} exit=${r.exit} ${r.ms}ms`
    );
    if (!ok && r.tail) console.log(`   ↳ ${r.tail.replace(/\n/g, ' | ')}`);
  }
  fs.writeFileSync(path.join(RESULTS, 'summary.json'), JSON.stringify({ at: new Date().toISOString(), rows }, null, 2));
  const missed = rows.filter((r) => r.vuln && !r.hit);
  const fps = rows.filter((r) => !r.vuln && r.hit);
  console.log(`\n真值漏检 ${missed.length} / 安全误报 ${fps.length}`);
  if (missed.length) console.log('漏检：' + missed.map((m) => m.id).join(', '));
  if (fps.length) console.log('误报：' + fps.map((m) => m.id).join(', '));
} catch (e) {
  console.error('BLOCKED:', e.message);
  if (serverLog) console.error(serverLog.slice(0, 2000));
  exitCode = 2;
} finally {
  child.kill();
  fs.writeFileSync(path.join(RESULTS, 'server.log'), serverLog);
}
process.exit(exitCode);

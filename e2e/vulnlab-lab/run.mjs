// ============================================================================
// e2e/vulnlab-lab/run.mjs —— [D156 2026-10-25] 外部裁判 5 号：VulnLab（PHP + pdo_sqlite）
//
// ── 为什么再加一个外部靶场（前有 Juice Shop/VAmPI/DVWA/Benchmark 四位）─────────
// W43 竞品对标（docs/竞品对标-2026W43.md）排队项。VulnLab（hediwen831-star/vulnlab）
// 带来前四位都没有的形态：**同一漏洞的三档实现挂在同一个应用里**——
//   · low.php    未防护（数字型直拼，页面回显实际执行 SQL）      预期：检出
//   · medium.php 黑名单防护但非递归替换（官方标注「双写可绕」）  预期：检出
//   · high.php   参数化（:id 预编译，功能完整）                  预期：**零检出**
// 真值来自**外部仓库自带的 Ground Truth Manifest**（benchmark/manifest.yaml：
// low/medium → vulnerable，high → negative 且「high 档上的任何一条报告都是误报，
// 无需人工复核」），不是本仓出题本仓判卷。
//
// ── 与 VAmPI 裁判的差别 ─────────────────────────────────────────────────────
// VAmPI 是「两个实例、同路径、官方开关」；VulnLab 是「一个实例、三条路径、
// 官方三档」——误报诱饵从「另一个实例」变成「同应用里修复档页面」，且修复档
// 由对方 CI 的 52 条绕过尝试断言守护（真值失效对方 CI 先红）。
//
// ── 自拉自收（redteam-lab 形态，非长驻依赖）──────────────────────────────────
// 靶场零依赖（php -S + pdo_sqlite，SQLite 首次访问自动建库）：
//   · 本机 PHP 常被 php.ini 锁死为 MySQL 形态（DVWA 用）⇒ 用 `php -n -d extension=…`
//     独立加载 pdo_sqlite，**不改共享 php.ini**；
//   · 未 clone 时自动 `git clone --depth 1`（CI ubuntu 自带 php+pdo_sqlite，
//     因此本裁判在 CI 可真实执行，而非像 VAmPI 那样环境性 SKIP）；
//   · 已在跑（同端口同应用）则复用不重复拉起；自己起的自己收。
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.VULNLAB_PORT || 8135);
const BASE = `http://127.0.0.1:${PORT}`;
const REPO = 'https://github.com/hediwen831-star/vulnlab';
const LAB_DIR = process.env.VULNLAB_DIR
  || join(process.env.LOCALAPPDATA || join(process.env.USERPROFILE || '', 'AppData', 'Local'), 'Temp', 'verify-labs', 'vulnlab');
const RESULTS_DIR = join(HERE, 'results');

// 三档真值端点（external manifest：low/med=vulnerable，high=negative）
const TIERS = [
  { tier: 'low', path: '/sqli/low.php', expect: 'detect', why: '数字型直拼（无引号无预处理）' },
  { tier: 'medium', path: '/sqli/medium.php', expect: 'detect', why: '黑名单非递归替换，官方标注双写可绕' },
  { tier: 'high', path: '/sqli/high.php', expect: 'clean', why: ':id 参数化预编译（修复对照档）' },
];

const SCAN_CFG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 15000,
  // SQLite 无 SLEEP ⇒ time 通道恒空载，砍掉省请求（union/boolean/error 三通道覆盖真值形态）
  techniques: ['union', 'boolean', 'error'],
  enableExtract: false,
  level: 2,
  risk: 2,
};
const PER_SCAN_TIMEOUT_MS = 240000;
// [D113 教训] 防自欺：请求数过少的「零检出」是没测过，不是测了没洞
const MIN_REQUESTS = 25;

/** @returns {string|null} 可用 php 可执行文件（PHP_EXE → 本机 php83 → PATH php） */
function findPhp() {
  const candidates = [process.env.PHP_EXE, 'D:/tools/php83/php.exe'].filter(Boolean);
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  const r = spawnSync('php', ['-v'], { encoding: 'utf8', shell: process.platform === 'win32' });
  return r.status === 0 ? 'php' : null;
}

/** php 启动参数：共享 php.ini 可能锁死为 MySQL 形态 ⇒ -n 裸启 + 按需补 pdo_sqlite */
function phpServerArgs(docRoot) {
  const args = ['-n'];
  const mods = spawnSync(PHP, ['-n', '-m'], { encoding: 'utf8', shell: process.platform === 'win32' });
  const hasSqlite = (mods.stdout || '').toLowerCase().includes('pdo_sqlite');
  if (!hasSqlite && process.platform === 'win32') {
    const extDir = join(dirname(PHP), 'ext');
    if (existsSync(join(extDir, 'php_pdo_sqlite.dll'))) {
      args.push(`-d`, `extension_dir=${extDir}`, `-d`, 'extension=pdo_sqlite');
    }
  }
  args.push('-S', `127.0.0.1:${PORT}`, '-t', docRoot);
  return args;
}

async function reachable() {
  try {
    const res = await fetch(`${BASE}/sqli/low.php?id=1`, { signal: AbortSignal.timeout(4000) });
    const body = await res.text();
    return res.ok && /VulnLab|SELECT/i.test(body) ? 'reused' : null; // 端口在跑但不是 VulnLab ⇒ 不复用
  } catch {
    return null;
  }
}

async function scanTier(t) {
  const sm = new ScanManager({});
  const id = await sm.start({ url: `${BASE}${t.path}?id=1`, config: { ...SCAN_CFG, testParameter: ['id'] } });
  const t0 = Date.now();
  for (;;) {
    const st = sm.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) {
      const rep = sm.getReport(id) || {};
      const counts = rep.summary?.validity?.counts || {};
      const vulns = rep.vulns || [];
      return {
        requests: counts.total || 0,
        verdict: rep.summary?.verdict || '-',
        reliable: rep.summary?.validity?.reliable !== false,
        vulns: vulns.map((v) => `${v.technique}·${v.param || '?'}·${v.riskLevel}`),
      };
    }
    if (Date.now() - t0 > PER_SCAN_TIMEOUT_MS) {
      sm.stop(id);
      return { requests: 0, verdict: 'timeout', reliable: false, vulns: [] };
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

// ── 前置：php / 靶场目录 / 服务 ──────────────────────────────────────────────
const PHP = findPhp();
if (!PHP) {
  console.log('[SKIP] VulnLab 靶场不可用：未找到 php（PHP_EXE 可指定路径；本裁判需 php -S + pdo_sqlite）');
  process.exit(0);
}
if (!existsSync(join(LAB_DIR, 'html', 'sqli', 'low.php'))) {
  console.log(`[lab] VulnLab 未部署（${LAB_DIR}），自动 clone ${REPO}`);
  const r = spawnSync('git', ['clone', '--depth', '1', REPO, LAB_DIR], { encoding: 'utf8', shell: process.platform === 'win32' });
  if (r.status !== 0 || !existsSync(join(LAB_DIR, 'html', 'sqli', 'low.php'))) {
    console.log(`[SKIP] VulnLab 靶场不可用：clone 失败（${(r.stderr || r.stdout || '').split('\n')[0]}）`);
    process.exit(0);
  }
}

let spawned = null;
let upState = await reachable();
if (!upState) {
  spawned = spawn(PHP, phpServerArgs(join(LAB_DIR, 'html')), { stdio: 'ignore', detached: false });
  for (let i = 0; i < 20 && !upState; i++) {
    await new Promise((r) => setTimeout(r, 500));
    upState = await reachable();
  }
}
if (!upState) {
  console.log(`[SKIP] VulnLab 靶场不可达（${BASE} php=${PHP}）—— 起 php -S 失败，见上方日志`);
  if (spawned) { try { spawned.kill(); } catch { /* best effort */ } }
  process.exit(0);
}
console.log(`[lab] VulnLab 就绪：${BASE}（${upState === 'reused' ? '复用已跑实例' : '本次自起 ' + PHP}）`);
console.log('[lab] 外部真值：benchmark/manifest.yaml 三档映射（low/med=vulnerable，high=negative 修复对照）');

// ── [D162 2026-10-25] 自证探针：靶场行为先符合官方真值的最低形态，才允许裁判引擎 ──
// CI 实测教训（run 40172892226 的 e2e-self-contained）：CI 上三档各 105 请求、
// verdict 干净的 no_vulnerability_detected——引擎认真测了，但靶场对任何输入无差分
// 响应（疑似该环境 SQLite 建库/种子失败致页面形态统一）。此时报「漏检」是错误归因：
// 靶场部署问题 ≠ 引擎漏检。探针用官方 manifest 的最低真值（low 档数字型直拼，
// `1 OR 1=1` 必须命中多行改变响应；本机实测 +11%）把两者分开。
async function selfTruthProbe() {
  const get = async (q) => {
    try {
      const r = await fetch(`${BASE}/sqli/low.php?id=${encodeURIComponent(q)}`, { signal: AbortSignal.timeout(8000) });
      return { ok: r.ok, len: (await r.text()).length };
    } catch {
      return { ok: false, len: 0 };
    }
  };
  const a = await get('1');
  const b = await get('1 OR 1=1');
  const diffPct = a.len > 0 ? Math.abs(b.len - a.len) / a.len : 1;
  return { a, b, diffPct, pass: a.ok && b.ok && diffPct > 0.03 };
}
const probe = await selfTruthProbe();
if (!probe.pass) {
  console.log(
    `[SKIP] VulnLab 靶场行为与官方真值不符（low.php 对 "1 OR 1=1" 无差分响应：基线 ${probe.a.len}B vs ` +
    `探针 ${probe.b.len}B，差 ${(((probe.b.len - probe.a.len) / (probe.a.len || 1)) * 100).toFixed(1)}%）` +
    '—— 靶场部署环境问题（非引擎漏检）；本裁判只在靶场行为符合其 manifest 最低真值时裁决引擎'
  );
  if (spawned) { try { spawned.kill(); } catch { /* best effort */ } }
  process.exit(0);
}
console.log(`[lab] 自证探针通过：low.php 基线 ${probe.a.len}B → OR 1=1 ${probe.b.len}B（${probe.b.len >= probe.a.len ? '+' : ''}${(((probe.b.len - probe.a.len) / (probe.a.len || 1)) * 100).toFixed(1)}%，符合官方真值形态）`);

// ── 三档扫描 + 裁决 ──────────────────────────────────────────────────────────
const rows = [];
let missDetect = 0;
let falsePositive = 0;
let weakEvidence = 0;
for (const t of TIERS) {
  const r = await scanTier(t);
  const detected = r.vulns.length > 0;
  const weak = r.requests < MIN_REQUESTS || !r.reliable;
  if (weak) weakEvidence += 1;
  // 漏检口径从严：真值档没检出就是漏检（无论是没测成还是测了没报——weak 另行披露原因）
  if (t.expect === 'detect' && !detected) missDetect += 1;
  if (t.expect === 'clean' && detected) falsePositive += 1;
  rows.push({ ...t, ...r, detected, weak });
  console.log(
    `[${t.expect === 'detect' ? '真值档' : '修复档'}] ${t.tier}.php ${t.why} → ` +
    `${detected ? `检出 ${r.vulns.length} 条（${r.vulns.join('、')}）` : '未检出'} · ` +
    `请求 ${r.requests} · verdict=${r.verdict}${weak ? ' ⚠证据不足' : ''}`
  );
}

const truthTotal = TIERS.filter((t) => t.expect === 'detect').length;
const pass = missDetect === 0 && falsePositive === 0 && weakEvidence === 0;
console.log('');
console.log(`真值漏洞档位：检出 ${truthTotal - missDetect}/${truthTotal}（漏检 ${missDetect}）`);
console.log(`修复档误报：${falsePositive}/1（high 参数化，manifest 标注任何报告均为误报）`);
if (weakEvidence > 0) console.log(`证据不足（请求<${MIN_REQUESTS} 或结论不可信）：${weakEvidence} 个档位`);
console.log(pass ? 'VulnLab 外部裁判通过' : 'VulnLab 外部裁判未通过（漏检/误报/证据不足，见上）');

// ── 结果落盘 ─────────────────────────────────────────────────────────────────
mkdirSync(RESULTS_DIR, { recursive: true });
const stamp = new Date().toISOString().slice(0, 10);
writeFileSync(
  join(RESULTS_DIR, `external-judge-${stamp}-d156.md`),
  `# 外部裁判 5 号 · VulnLab（${new Date().toISOString()}）\n\n` +
  `- 靶场：${REPO}（${LAB_DIR}，php=${PHP}，${BASE}）\n- 真值来源：对方 benchmark/manifest.yaml（三档映射 + high 档 52 条绕过断言守护）\n\n` +
  `| 档位 | 语义 | 预期 | 实测 | 请求 | verdict |\n|---|---|---|---|---|---|\n` +
  rows.map((r) => `| ${r.tier} | ${r.why} | ${r.expect === 'detect' ? '检出' : '零检出'} | ${r.detected ? r.vulns.join('、') || '检出' : '未检出'} | ${r.requests} | ${r.verdict} |`).join('\n') +
  `\n\n结论：${pass ? '通过（真值档全检出 + 修复档零误报 + 证据充分）' : '未通过'}\n`,
  'utf8'
);

if (spawned) {
  try { spawned.kill(); } catch { /* best effort */ }
}
process.exit(pass ? 0 : 1);

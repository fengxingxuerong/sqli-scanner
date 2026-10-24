#!/usr/bin/env node
// ============================================================================
// bench/run.mjs —— [D147 2026-10-24] 公开可复现基准：本引擎 vs sqlmap（第三方 DVWA）
//
// 为什么不是又一个自建靶场：仓内已有 e2e/sqlmap-benchmark（sqli-labs Python 复刻），
// 但那是「自己出题自己判卷」。本基准只选 **第三方官方靶场 DVWA** 的官方安全分档
// （low / medium / impossible），真值来自 DVWA 源码，不是本仓断言。
//
// 用例（5 个，3 漏洞 + 2 安全；**样本很小，不能外推成通用检出率**）：
//   GET  low        /vulnerabilities/sqli/?id=1          官方 low.php 单引号直拼
//   POST medium     /vulnerabilities/sqli/               官方 medium.php 数值型无引号 + 转义绕过
//   GET  low        /vulnerabilities/sqli_blind/?id=1    官方盲注（无错误回显）
//   GET  impossible 同两条路径的 PDO 参数化档           必须零检出
//
// 同条件口径：
//   · 双方都 level=2 / risk=1 / 单线程 / 检测技术 BEUSTQ；
//   · sqlmap 固定 1.10.7（结果里记录版本）；本引擎版本取 package.json；
//   · 每例可 --runs=N：检出取多数决、耗时取中位数、技术取命中轮并集；
//   · 安全例的本引擎请求数 < 30 视为「没测成」，不计入零误报证据（同 DVWA 外部裁判口径）。
//
// 产物：bench/results/<timestamp>/{summary.json,summary.md,raw/*}
// 用法：
//   node bench/run.mjs --runs=3        # 推荐：三轮中位
//   node bench/run.mjs --selftest      # 纯判据自证（不起靶场/不跑 sqlmap）
//   node bench/run.mjs --strict        # 本引擎出现漏检/误报时 exit 1（默认只报告）
// 前置：DVWA 在 DVWA_BASE（默认 http://127.0.0.1:8099）可访问；sqlmap 在 PATH。
//       未就绪时输出 [SKIP] 并 exit 0（不计通过，也不伪造数字）。
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../server/src/engine/ScanManager.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.DVWA_BASE || 'http://127.0.0.1:8099';
const SQLMAP = process.env.SQLMAP_BIN || 'sqlmap';
const SQLMAP_TIMEOUT_MS = Number(process.env.BENCH_SQLMAP_TIMEOUT_MS) || 180000;
const SCAN_TIMEOUT_MS = Number(process.env.BENCH_SCAN_TIMEOUT_MS) || 120000;
const TAG = '[bench]';
const args = process.argv.slice(2);
const RUNS = Math.min(5, Math.max(1, Number((args.find((a) => a.startsWith('--runs=')) || '').split('=')[1]) || 1));
const STRICT = args.includes('--strict');
const OUT_DIR = join(ROOT, 'bench', 'results', new Date().toISOString().replace(/[:.]/g, '-'));
const SESSION = 'bench-session';

const CASES = [
  {
    id: 'dvwa-get-low',
    kind: 'vuln',
    method: 'GET',
    path: '/vulnerabilities/sqli/?id=1&Submit=Submit',
    level: 'low',
    param: 'id',
    desc: 'GET id 直拼（官方 low.php 单引号 + mysqli_error 回显）',
  },
  {
    id: 'dvwa-post-medium',
    kind: 'vuln',
    method: 'POST',
    path: '/vulnerabilities/sqli/',
    level: 'medium',
    param: 'id',
    body: 'id=1&Submit=Submit',
    bodyParams: { id: '1', Submit: 'Submit' },
    desc: 'POST 表单 + 转义绕过（官方 medium.php 数值型无引号）',
  },
  {
    id: 'dvwa-blind-low',
    kind: 'vuln',
    method: 'GET',
    path: '/vulnerabilities/sqli_blind/?id=1&Submit=Submit',
    level: 'low',
    param: 'id',
    desc: '盲注（官方 low.php 去掉 or die，仅布尔可分）',
  },
  {
    id: 'dvwa-safe-impossible',
    kind: 'safe',
    method: 'GET',
    path: '/vulnerabilities/sqli/?id=1&Submit=Submit',
    level: 'impossible',
    param: 'id',
    noPrune: true,
    desc: '同路径 impossible 档（官方 PDO prepare + is_numeric）',
  },
  {
    id: 'dvwa-safe-blind-impossible',
    kind: 'safe',
    method: 'GET',
    path: '/vulnerabilities/sqli_blind/?id=1&Submit=Submit',
    level: 'impossible',
    param: 'id',
    noPrune: true,
    desc: '盲注同路径 impossible 档（PDO + CSRF token）',
  },
];

const SCAN_CFG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 15000,
  techniques: ['union', 'error', 'boolean', 'time', 'stacked'],
  enableExtract: false,
  level: 2,
  risk: 1,
  productionMode: false,
};

const cookieHeader = (c) => `security=${c.level}; PHPSESSID=${SESSION}`;
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
};

/** 从 sqlmap 文本里判定是否检出（只认 Type 行，避免把启发式提示当结论）。 */
function sqlmapVerdict(out) {
  const techniques = [];
  const map = [
    ['boolean', /Type:\s*boolean-based blind/i],
    ['time', /Type:\s*time-based blind/i],
    ['union', /Type:\s*UNION query/i],
    ['error', /Type:\s*error-based/i],
    ['stacked', /Type:\s*stacked queries/i],
    ['inline', /Type:\s*inline queries/i],
  ];
  for (const [name, re] of map) if (re.test(out)) techniques.push(name);
  const explicitNo = /all tested parameters do not appear to be injectable|does not seem to be injectable|no injectable parameters/i.test(out);
  // `Type:` 行只在 sqlmap 确认注入点时输出；启发式提示（might be injectable）不产生 Type 行。
  // 不要再要求 "is vulnerable" —— 真实输出常用 "appears to be ... injectable" 的中缀形态。
  return { hit: !explicitNo && techniques.length > 0, techniques };
}

/** 本引擎跑一次。 */
async function scanOnce(c) {
  const sm = new ScanManager({});
  const target = {
    url: `${BASE}${c.path}`,
    cookieParams: { security: c.level, PHPSESSID: SESSION },
    config: { ...SCAN_CFG, testParameter: [c.param], ...(c.noPrune ? { validationSkip: false } : {}) },
  };
  if (c.method === 'POST') {
    target.method = 'POST';
    target.bodyParams = { ...c.bodyParams };
  }
  const id = await sm.start(target);
  const t0 = Date.now();
  for (;;) {
    const st = sm.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) break;
    if (Date.now() - t0 > SCAN_TIMEOUT_MS) { sm.stop(id); return { hit: false, techniques: [], requests: 0, ms: Date.now() - t0, verdict: 'timeout', error: 'timeout' }; }
    await new Promise((r) => setTimeout(r, 100));
  }
  const rep = sm.getReport(id) || {};
  const vulns = rep.vulns || [];
  return {
    hit: vulns.length > 0,
    techniques: [...new Set(vulns.map((v) => v.technique).filter(Boolean))],
    requests: rep.summary?.validity?.counts?.total || 0,
    ms: Date.now() - t0,
    verdict: rep.summary?.verdict || null,
    dbms: rep.summary?.dbmsEvidence?.dbms || null,
  };
}

/** sqlmap 跑一次；返回 {hit, techniques, ms, timedOut}。 */
function sqlmapOnce(c, rawFile) {
  return new Promise((resolveP, reject) => {
    const url = `${BASE}${c.path}`;
    const argv = [
      '-u', url, '--batch', '--level=2', '--risk=1', '--threads=1',
      '--technique=BEUSTQ', '--no-cast', '--flush-session',
      '-p', c.param, '--cookie', cookieHeader(c),
      '--timeout=10', '--retries=1', '--output-dir', join(OUT_DIR, 'raw'),
    ];
    if (c.method === 'POST') argv.push('--data', c.body);
    const t0 = Date.now();
    const proc = spawn(SQLMAP, argv, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let settled = false;
    const finish = (extra = {}) => {
      if (settled) return;
      settled = true;
      writeFileSync(rawFile, out, 'utf8');
      resolveP({ ...sqlmapVerdict(out), ms: Date.now() - t0, ...extra });
    };
    const timer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch { /* noop */ }
      finish({ timedOut: true });
    }, SQLMAP_TIMEOUT_MS);
    proc.stdout.on('data', (d) => { out += d.toString('utf8'); });
    proc.stderr.on('data', (d) => { out += d.toString('utf8'); });
    proc.on('error', (e) => { clearTimeout(timer); reject(e); });
    proc.on('close', () => { clearTimeout(timer); finish(); });
  });
}

/** 同一用例跑 N 次：检出多数决、耗时中位、技术并集。 */
async function repeat(fn, n) {
  const runs = [];
  for (let i = 0; i < n; i++) runs.push(await fn(i));
  return {
    hit: runs.filter((r) => r.hit).length > n / 2,
    techniques: [...new Set(runs.flatMap((r) => r.techniques))],
    ms: median(runs.map((r) => r.ms)),
    requests: median(runs.map((r) => r.requests || 0)),
    hitCount: runs.filter((r) => r.hit).length,
    verdict: runs[runs.length - 1]?.verdict ?? null,
    dbms: runs.find((r) => r.dbms)?.dbms ?? null,
    timedOut: runs.some((r) => r.timedOut || r.error === 'timeout'),
  };
}

/** 汇总：只做 TP/FN/FP/TN 与「安全例证据不足」计数。 */
function summarize(rows) {
  const score = (side) => {
    let tp = 0, fn = 0, fp = 0, tn = 0;
    for (const r of rows) {
      if (r.kind === 'vuln') r[side].hit ? tp++ : fn++;
      else if (r[side].hit) fp++;
      else if (r[side].weak) continue;
      else tn++;
    }
    return { tp, fn, fp, tn };
  };
  return { ours: score('ours'), sqlmap: score('sqlmap') };
}

function toolVersion() {
  const r = spawnSync(SQLMAP, ['--version'], { encoding: 'utf8' });
  const text = `${r.stdout || ''}\n${r.stderr || ''}`;
  // sqlmap 的 pip wrapper 会在版本行后打印 "Press Enter..." 与 "[ERROR] exit"，
  // 不能取末行；只认 x.y[.z] 形态的版本号。
  const m = text.match(/(?:^|\s)(\d+\.\d+(?:\.\d+)?(?:[#\w.-]*))/);
  return m ? m[1] : null;
}

function dvwaSourceHashes() {
  const dir = process.env.DVWA_DIR;
  if (!dir) return null;
  const files = ['low.php', 'medium.php', 'impossible.php'];
  const out = {};
  for (const f of files) {
    try {
      out[f] = createHash('sha256').update(readFileSync(join(dir, 'vulnerabilities', 'sqli', 'source', f))).digest('hex').slice(0, 16);
    } catch {
      out[f] = null;
    }
  }
  return out;
}

async function targetReady() {
  try {
    const r = await fetch(`${BASE}/login.php`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return false;
    const t = await r.text();
    return /Damn Vulnerable Web Application|DVWA/i.test(t);
  } catch {
    return false;
  }
}

function renderMarkdown(meta) {
  const lines = [
    '# Public benchmark: sqli-scanner vs sqlmap (DVWA)',
    '',
    `- 日期：${meta.date}`,
    `- 目标：${meta.base}（第三方 DVWA，官方安全分档）`,
    `- 我方：${meta.oursVersion}（level=2 / risk=1 / threads=1 / 技术 BEUSTQ）`,
    `- sqlmap：${meta.sqlmapVersion ?? '未记录'}（--level=2 --risk=1 --threads=1 --technique=BEUSTQ）`,
    `- 轮次：每例 ${meta.runs} 次（检出多数决、耗时中位、技术并集）`,
    `- DVWA 源码哈希：${meta.hashes ? JSON.stringify(meta.hashes) : '未设置 DVWA_DIR，未记录'}`,
    '',
    '| 用例 | 类型 | 预期 | 我方 | 技术 | 请求数 | 耗时 | sqlmap | 技术 | 耗时 |',
    '|---|---|---|---|---:|---:|---:|---|---|---:|',
    ...meta.rows.map((r) => `| ${r.id} | ${r.kind} | ${r.kind === 'vuln' ? '检出' : '零检出'} | ${r.ours.hit ? '命中' : '未命中'}${r.ours.weak ? '（证据不足）' : ''} | ${r.ours.techniques.join('/') || '-'} | ${r.ours.requests || '-'} | ${r.ours.ms}ms | ${r.sqlmap.hit ? '命中' : '未命中'} | ${r.sqlmap.techniques.join('/') || '-'} | ${r.sqlmap.ms}ms |`),
    '',
    '## 汇总（5 例小样本，不可外推为通用检出率）',
    '',
    `- 我方：TP ${meta.summary.ours.tp} / FN ${meta.summary.ours.fn} / FP ${meta.summary.ours.fp} / TN ${meta.summary.ours.tn}`,
    `- sqlmap：TP ${meta.summary.sqlmap.tp} / FN ${meta.summary.sqlmap.fn} / FP ${meta.summary.sqlmap.fp} / TN ${meta.summary.sqlmap.tn}`,
    `- 安全例请求数 < 30（视为没测成）：${meta.rows.filter((r) => r.ours.weak).map((r) => r.id).join(', ') || '无'}`,
    '',
    '## 口径与边界',
    '',
    '- sqlmap 只做检测阶段（未拖库/未 os-shell），与本工具同定位；耗时是各自策略下的墙钟时间，不是逐请求成本。',
    '- 5 个用例来自 DVWA 官方 low/medium/impossible 分档，样本很小；结果**不能**外推成通用检出率或误报率。',
    '- 本基准不替代 acceptance / 外部裁判；它只回答「同一组第三方端点上，双方结论是否一致」。',
    '- 复现：先启动 DVWA（`node scripts/labs.mjs --up=mariadb,dvwa`），再 `npm run bench:sqlmap -- --runs=3`。',
    '',
  ];
  return lines.join('\n');
}

async function main() {
  if (!(await targetReady())) {
    console.log(`${TAG} [SKIP] DVWA 不可达（${BASE}）—— 先 node scripts/labs.mjs --up=mariadb,dvwa；不计通过`);
    return 0;
  }
  const sqlmapVersion = toolVersion();
  if (!sqlmapVersion) {
    console.log(`${TAG} [SKIP] 未找到 sqlmap（SQLMAP_BIN=${SQLMAP}）；无法做同题对照，不计通过`);
    return 0;
  }
  mkdirSync(join(OUT_DIR, 'raw'), { recursive: true });
  const rows = [];
  for (const c of CASES) {
    process.stdout.write(`${TAG} ${c.id} … `);
    const ours = await repeat((i) => scanOnce(c), RUNS);
    const sqlmap = await repeat((i) => sqlmapOnce(c, join(OUT_DIR, 'raw', `sqlmap-${c.id}-run${i + 1}.txt`)), RUNS);
    const weak = c.kind === 'safe' && !ours.hit && ours.requests < 30;
    rows.push({ ...c, ours: { ...ours, weak }, sqlmap });
    console.log(`我方 ${ours.hit ? 'HIT' : 'miss'} ${ours.ms}ms · sqlmap ${sqlmap.hit ? 'HIT' : 'miss'} ${sqlmap.ms}ms${weak ? ' · 安全例证据不足' : ''}`);
  }
  const meta = {
    date: new Date().toISOString(),
    base: BASE,
    runs: RUNS,
    oursVersion: JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version,
    sqlmapVersion,
    hashes: dvwaSourceHashes(),
    rows,
    summary: summarize(rows),
  };
  writeFileSync(join(OUT_DIR, 'summary.json'), JSON.stringify(meta, null, 2) + '\n', 'utf8');
  writeFileSync(join(OUT_DIR, 'summary.md'), renderMarkdown(meta) + '\n', 'utf8');
  const s = meta.summary;
  console.log(`\n${TAG} 我方 TP=${s.ours.tp} FN=${s.ours.fn} FP=${s.ours.fp} TN=${s.ours.tn} | sqlmap TP=${s.sqlmap.tp} FN=${s.sqlmap.fn} FP=${s.sqlmap.fp} TN=${s.sqlmap.tn}`);
  console.log(`${TAG} 产物：${OUT_DIR}`);
  const bad = s.ours.fn + s.ours.fp > 0;
  return STRICT && bad ? 1 : 0;
}

function selftest() {
  const checks = [
    ['sqlmap 阳性样本可识别', sqlmapVerdict('Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\n[INFO] the back-end DBMS is MySQL').hit === true],
    ['sqlmap 明确否定样本不误报', sqlmapVerdict('all tested parameters do not appear to be injectable').hit === false],
    ['无 Type 行不得算命中', sqlmapVerdict('might be injectable, but no Type line').hit === false],
    ['中位数（奇数）', median([3, 1, 2]) === 2],
    ['中位数（偶数，四舍五入）', median([4, 1, 3, 2]) === 3],
    ['汇总计数', (() => {
      const rows = [
        { kind: 'vuln', ours: { hit: true }, sqlmap: { hit: true } },
        { kind: 'vuln', ours: { hit: false }, sqlmap: { hit: true } },
        { kind: 'safe', ours: { hit: false, weak: false }, sqlmap: { hit: false } },
        { kind: 'safe', ours: { hit: true, weak: false }, sqlmap: { hit: false } },
      ];
      const s = summarize(rows);
      return s.ours.tp === 1 && s.ours.fn === 1 && s.ours.fp === 1 && s.ours.tn === 1;
    })()],
    ['安全例证据不足不计 TN', (() => {
      const s = summarize([{ kind: 'safe', ours: { hit: false, weak: true }, sqlmap: { hit: false } }]);
      return s.ours.tn === 0;
    })()],
  ];
  const bad = checks.filter(([, ok]) => !ok).map(([name]) => name);
  if (bad.length) {
    console.error(`${TAG} ✗ selftest 失败：\n  - ${bad.join('\n  - ')}`);
    process.exitCode = 1;
  } else {
    console.log(`${TAG} ✓ selftest 通过（7 条：解析 / 否定 / 中位 / 汇总 / 弱证据）`);
  }
}

if (args.includes('--selftest')) selftest();
else process.exitCode = await main();

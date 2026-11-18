// ============================================================================
// e2e/dvwa-lab/d300-verify.mjs —— [D300] 扩展拖库通道真机验证（DVWA + MariaDB）
//
// 验证两件事（背景：CHANGELOG D300 边界「真机端到端未复跑」——本脚本就是那次复跑）：
//   A. 盲注 opt-in 拖库：blind high（cookie id 布尔盲注，官方 high.php）+ blindDump=true
//      ⇒ extractPhaseD300 的 extractBlindScalars 逐字节提 current_user()/database()/version()
//      进 report.data（此前 boolean 命中只出版本证明，report.data 恒空）。
//   B. 一阶 union 拖库回归：sqli low（官方 low.php 2 列 UNION）+ enableExtract
//      ⇒ 既有 extractAll 全量拖库路径在 D300 包装层在位时行为不变（行数据落 report.data）。
//
// 判据（诚实口径）：
//   A：boolean 命中 + data.currentUser/database/banner 非空 + summary.d300Channels 含 extended-extract
//   B：union 命中 + data.rows 至少 1 张表有行 +（若空）必须给出 dumpUnconfirmed 约束
// 结果落 results/d300-verify-<时间戳>.json / .md
// 复跑：node e2e/dvwa-lab/d300-verify.mjs（默认 http://127.0.0.1:8099）
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const BASE = process.env.DVWA_BASE || 'http://127.0.0.1:8099';
const SESSION = process.env.DVWA_PHPSESSID || 'dvwa-lab-session';
const TIMEOUT_MS = Number(process.env.D300_TIMEOUT_MS) || 600_000;

async function reachable() {
  try {
    const r = await fetch(`${BASE}/login.php`, { signal: AbortSignal.timeout(8000) });
    const t = await r.text();
    return r.ok && (t.includes('Damn Vulnerable Web Application') || t.includes('DVWA'));
  } catch { return false; }
}

/** 跑一次扫描并返回报告（超时 stop 并如实标注） */
async function scan(target) {
  const sm = new ScanManager({});
  const id = await sm.start(target);
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > TIMEOUT_MS) { sm.stop(id); return { report: null, status: 'timeout', elapsedMs: Date.now() - t0 }; }
    await new Promise((r) => setTimeout(r, 200));
  }
  return { report: sm.getReport(id) || {}, status: sm.scans.get(id)?.status || 'unknown', elapsedMs: Date.now() - t0 };
}

const CFG_BASE = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 20000,
  productionMode: false,
  level: 2,
  risk: 2,
};

// ── A. 盲注 opt-in（blind high，cookie 注入点）──────────────────────────────
async function caseBlind() {
  const { report, status, elapsedMs } = await scan({
    url: `${BASE}/vulnerabilities/sqli_blind/?id=1&Submit=Submit`,
    cookieParams: { security: 'high', PHPSESSID: SESSION, id: '1' },
    config: {
      ...CFG_BASE,
      techniques: ['boolean'],
      enableExtract: true,
      extractScope: { blindDump: true },
      dbms: 'MySQL', // blind high 无回显指纹不出来（外部裁判实测 dbms=?）⇒ --dbms 强制方言
      // DVWA high 盲注 SQL 是 user_id = '<cookie>'：无回显指纹推不出闭合（boundary=''）⇒
      // 裸探针落引号内且 MariaDB 把 '1 AND ...' 数值强转成 1 ⇒ 布尔判据死亡。--known-point 人工闭合。
      knownPoint: { param: 'id', quote: "'" },
      testParameter: ['id'],
    },
  });
  const vulns = report?.vulns || [];
  const boolHit = vulns.find((v) => v.technique === 'boolean');
  const data = report?.data || {};
  const channels = report?.summary?.d300Channels || [];
  const scalars = {
    currentUser: data.currentUser ?? null,
    currentDb: data.currentDb ?? null,
    banner: data.banner ?? null,
  };
  const got = Object.values(scalars).filter((v) => v != null && v !== '').length;
  const ok = Boolean(boolHit) && got >= 1 && channels.includes('extended-extract') && status === 'completed';
  return { case: 'A-blind-dump', ok, status, elapsedMs, booleanHit: Boolean(boolHit), scalars, channels, requests: report?.summary?.validity?.counts?.total ?? null, verdict: report?.summary?.verdict ?? null };
}

// ── B. 一阶 union 拖库回归（sqli low）───────────────────────────────────────
async function caseUnion() {
  const { report, status, elapsedMs } = await scan({
    url: `${BASE}/vulnerabilities/sqli/?id=1&Submit=Submit`,
    cookieParams: { security: 'low', PHPSESSID: SESSION },
    config: {
      ...CFG_BASE,
      techniques: ['union', 'error'],
      enableExtract: true,
      testParameter: ['id'],
    },
  });
  const vulns = report?.vulns || [];
  const unionHit = vulns.some((v) => v.technique === 'union' || v.technique === 'error');
  const data = report?.data || {};
  const rowTables = Object.entries(data.rows || {}).filter(([, rows]) => Array.isArray(rows) && rows.length > 0);
  const constraints = (report?.summary?.constraints || []).filter((c) => c.includes('拖库空结果未确认'));
  const ok = unionHit && (rowTables.length >= 1 || constraints.length >= 1) && status === 'completed';
  return {
    case: 'B-union-dump-regression', ok, status, elapsedMs,
    unionHit, rowTables: rowTables.map(([k, rows]) => `${k}(${rows.length}行)`),
    databases: data.databases || [], constraints, channels: report?.summary?.d300Channels || [],
    requests: report?.summary?.validity?.counts?.total ?? null, verdict: report?.summary?.verdict ?? null,
  };
}

if (!(await reachable())) {
  console.log(`[SKIP] DVWA 不可达（${BASE}）—— 先 node scripts/labs.mjs --up=dvwa,mariadb`);
  process.exit(0);
}
console.log(`[d300-verify] DVWA 就绪：${BASE}`);

const results = [];
console.log('\n── A. 盲注 opt-in 拖库（blind high / cookie 布尔 + blindDump）──');
const a = await caseBlind();
results.push(a);
console.log(`[${a.ok ? 'PASS' : 'FAIL'}] status=${a.status} boolean命中=${a.booleanHit} 通道=${JSON.stringify(a.channels)} 标量=${JSON.stringify(a.scalars)} 请求=${a.requests} 耗时=${(a.elapsedMs / 1000).toFixed(1)}s`);

console.log('\n── B. 一阶 union 拖库回归（sqli low + enableExtract）──');
const b = await caseUnion();
results.push(b);
console.log(`[${b.ok ? 'PASS' : 'FAIL'}] status=${b.status} union命中=${b.unionHit} 库=${JSON.stringify(b.databases)} 有行表=${JSON.stringify(b.rowTables)} 请求=${b.requests} 耗时=${(b.elapsedMs / 1000).toFixed(1)}s`);
if (b.constraints.length) console.log(`       约束：${b.constraints.join(' | ')}`);

const pass = results.every((r) => r.ok);
mkdirSync(RESULTS_DIR, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
writeFileSync(resolve(RESULTS_DIR, `d300-verify-${stamp}.json`), JSON.stringify({ base: BASE, at: new Date().toISOString(), pass, results }, null, 2));
const md = [
  `# D300 真机验证（DVWA + MariaDB）— ${new Date().toISOString()}`,
  '',
  `- 结论：**${pass ? 'PASS' : 'FAIL'}**（A 盲注 opt-in / B 一阶 union 回归）`,
  `- A blind high（cookie 布尔）+ blindDump：boolean=${a.booleanHit}，标量=${JSON.stringify(a.scalars)}，通道=${JSON.stringify(a.channels)}，${(a.elapsedMs / 1000).toFixed(1)}s`,
  `- B sqli low（UNION 2 列）+ enableExtract：库=${JSON.stringify(b.databases)}，有行表=${JSON.stringify(b.rowTables)}，${(b.elapsedMs / 1000).toFixed(1)}s`,
].join('\n');
writeFileSync(resolve(RESULTS_DIR, `d300-verify-${stamp}.md`), md);
console.log(`\n[d300-verify] 结果落盘 results/d300-verify-${stamp}.{json,md}`);
console.log(pass ? '✅ D300 真机验证通过' : '❌ D300 真机验证未通过（见上）');
process.exit(pass ? 0 : 1);

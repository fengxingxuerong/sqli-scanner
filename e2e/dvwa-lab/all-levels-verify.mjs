// ============================================================================
// e2e/dvwa-lab/all-levels-verify.mjs —— DVWA 全模块 × 全等级真机验证（sqli / sqli_blind × 4 档）
//
// 真值来源：.verify-labs/DVWA-master/vulnerabilities/{sqli,sqli_blind}/source/*.php（官方源码）
//   sqli  low      : GET id，user_id='$id'，mysqli_error 回显 ⇒ union/error/boolean + 拖库
//   sqli  medium   : POST id，real_escape_string 但数值型无引号 ⇒ union/error/boolean 检出；
//                    拖库 = 已知缺口（提取链 --hex 化未接，引号标记被全站转义致死，见 GAP①）
//   sqli  high     : 【session 型二阶】POST session-input.php 存 $_SESSION['id']（原样）→
//                    GET /vulnerabilities/sqli/ 读 session 拼 user_id='$id' LIMIT 1（2 列回显、
//                    报错抑制为 "Something went wrong."）⇒ 二阶检测 = 已知缺口（判定只认
//                    ERROR_SIG 报错回显，见 GAP②）；拖库走**直驱适配器**验证 D300 能力本体
//   sqli  impossible: PDO prepare + is_numeric ⇒ 0 检出（须打满请求预算）
//   blind low      : GET id，布尔 only
//   blind medium   : POST id，数值型布尔 only（real_escape_string，引号探针必死 ⇒ 不传 knownPoint）
//   blind high     : COOKIE id，引号布尔 only，MISSING 分支 404 + rand sleep ⇒ 需 knownPoint 闭合
//   blind impossible: PDO ⇒ 0 检出
//
// 判据（诚实口径，逐条落 JSON/MD）：
//   - 检出：命中技术 ⊇ must；impossible 档 0 检出且请求 ≥ 30（防「没测过」假阴性）
//   - 拖库：dump 出的 dvwa.users 行须命中种子用户名（admin/gordonb/1337/pablo/smithy ≥4/5）
//   - 盲注：currentUser 含 '@' 且 currentDb='dvwa' 且 banner 含 'MariaDB'（三标量全提）
//   - GAP 显式点名不计 FAIL（同 SKIP 语义：缺口要被看见，不被伪装成通过或失败）：
//     GAP① medium 拖库需提取链 --hex 化（hexLiteral.js 已有基建，未接 dumpData/extractScalar）
//     GAP② 二阶检测布尔差异判定路径（SecondOrderDetector 只认报错回显签名）
// 复跑：node scripts/labs.mjs --up=dvwa,mariadb && node e2e/dvwa-lab/all-levels-verify.mjs
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';
import { SYS_DBS } from '../../server/src/engine/scanHelpers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const BASE = process.env.DVWA_BASE || 'http://127.0.0.1:8099';
const SESSION = process.env.DVWA_PHPSESSID || 'dvwa-lab-session';
const TIMEOUT_MS = Number(process.env.ALL_LEVELS_TIMEOUT_MS) || 600_000;
const SEED_USERS = ['admin', 'gordonb', '1337', 'pablo', 'smithy'];
const SAFE_MIN_REQUESTS = 30;

const CFG_BASE = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 20000,
  productionMode: false,
  level: 2,
  risk: 2,
};

async function reachable() {
  try {
    const r = await fetch(`${BASE}/login.php`, { signal: AbortSignal.timeout(8000) });
    const t = await r.text();
    return r.ok && (t.includes('Damn Vulnerable Web Application') || t.includes('DVWA'));
  } catch { return false; }
}

async function scanOnce(target, timeoutMs = TIMEOUT_MS) {
  const sm = new ScanManager({});
  const id = await sm.start(target);
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > timeoutMs) { sm.stop(id); return { report: null, status: 'timeout', elapsedMs: Date.now() - t0 }; }
    await new Promise((r) => setTimeout(r, 200));
  }
  return { report: sm.getReport(id) || {}, status: sm.scans.get(id)?.status || 'unknown', elapsedMs: Date.now() - t0 };
}

function techs(report) {
  return [...new Set((report?.vulns || []).map((v) => v.technique))];
}

/** 拖库对账：dvwa.users 行文本须命中种子用户名（≥4/5，报告里逐个点名） */
function reconcileUsers(report) {
  const data = report?.data || {};
  const rowText = JSON.stringify(data.rows || {});
  const hits = SEED_USERS.filter((u) => rowText.includes(u));
  return { hits, total: SEED_USERS.length, rowTables: Object.entries(data.rows || {}).filter(([, r]) => Array.isArray(r) && r.length > 0).map(([k, r]) => `${k}(${r.length}行)`), dbs: data.databases || [] };
}

/** 盲注标量断言：三标量全提 + 通道标记 */
function checkScalars(report) {
  const d = report?.data || {};
  const s = { currentUser: d.currentUser ?? null, currentDb: d.currentDb ?? null, banner: d.banner ?? null };
  const ok =
    typeof s.currentUser === 'string' && s.currentUser.includes('@') &&
    s.currentDb === 'dvwa' &&
    typeof s.banner === 'string' && s.banner.includes('MariaDB');
  return { ok, scalars: s, channels: report?.summary?.d300Channels || [] };
}

// ── 直驱二阶拖库（sqli-high 拖库能力验证；不依赖检测判定）───────────────────
// 复刻 scan/extractExtended.js 的适配器语义（store→trigger + 状态码透传 + 串行），
// 用真实 Extractor/SecondOrderDetector 对真实 DVWA MariaDB 触发页拖库。
function pickUrlPayload(url) {
  if (typeof url !== 'string' || !/select/i.test(url)) return null;
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (typeof v === 'string' && /select/i.test(v)) return v;
    }
  } catch { /* 非 URL 形态跳过 */ }
  return null;
}

async function directSecondOrderDump(storePoint, securityLevel = 'high') {
  const sm = new ScanManager({});
  const target = {
    url: `${BASE}/vulnerabilities/sqli/session-input.php`,
    cookieParams: { security: securityLevel, PHPSESSID: SESSION },
    config: {
      concurrency: 1, ratePerSec: 0, retry: 0, timeoutMs: 20000, productionMode: false,
      dbms: 'MySQL', unionCols: '2', dumpConcurrency: 1, dumpDatabaseConcurrency: 1,
    },
  };
  const httpClient = sm.getScanClient('d300-direct-dump', target);
  const triggerUrl = `${BASE}/vulnerabilities/sqli/`;
  let lastStatus = null;
  const statusClient = {
    request: async (o) => { const r = await httpClient.request(o); lastStatus = r?.status ?? lastStatus; return r; },
  };
  const adapter = {
    request: async (opts) => {
      const payload = pickUrlPayload(opts?.url);
      if (payload == null) return { status: 0, data: '' };
      const soCtx = { target, config: target.config, point: storePoint };
      await sm.secondOrderDetector._store(statusClient, soCtx, payload);
      const body = await sm.secondOrderDetector._trigger(statusClient, soCtx, triggerUrl);
      return { status: lastStatus ?? 200, data: body };
    },
  };
  const dumpCtx = {
    httpClient: adapter, target,
    // 与 buildDumpCtx 同口径：哨兵原值（LIMIT 1 不截标记行）+ 回显列现场探测 + 串行
    point: { id: 'so-direct', location: 'url', param: 'id', actionUrl: triggerUrl, boundary: "'", originalValue: '999999999', echoCols: null, columns: Number(target.config.unionCols) || 2 },
    config: target.config, dbms: 'MySQL', scanId: 'd300-direct-dump',
  };
  const allDbs = await sm.extractor.enumerateDatabases(dumpCtx);
  const dbs = allDbs.filter((d) => !SYS_DBS.has(String(d).toLowerCase()));
  const dumped = await sm.extractor.dumpAllDatabases(dumpCtx, dbs, {});
  return { dbs, tables: dumped.tables, columns: dumped.columns, rows: dumped.rows, meta: dumped.meta };
}

// ── 各 case 的 target 构造与判据 ────────────────────────────────────────────
const CASES = [
  {
    name: 'sqli-low',
    desc: 'GET id 直拼 + mysqli_error 回显（官方 low.php）',
    must: ['union', 'boolean'],
    dumpCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli/?id=1&Submit=Submit`, cookieParams: { security: 'low', PHPSESSID: SESSION }, config: { ...CFG_BASE, enableExtract: true, testParameter: ['id'] } }),
    judge: (r) => ({ detected: r.must.every((t) => techs(r.report).includes(t)), dump: reconcileUsers(r.report) }),
  },
  {
    name: 'sqli-medium',
    desc: 'POST id + real_escape_string 但数值型无引号（官方 medium.php）——检测 + --hex 拖库（[D301] 引号字面量全 0x 化，转义无从作用）',
    must: ['union', 'boolean'],
    dumpCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli/`, method: 'POST', bodyParams: { id: '1', Submit: 'Submit' }, cookieParams: { security: 'medium', PHPSESSID: SESSION }, config: { ...CFG_BASE, enableExtract: true, hex: true, testParameter: ['id'] } }),
    judge: (r) => ({ detected: r.must.every((t) => techs(r.report).includes(t)), dump: reconcileUsers(r.report) }),
  },
  {
    name: 'sqli_blind-low',
    desc: 'GET id 布尔 only（官方去 or die）+ 盲注 opt-in 拖库',
    must: ['boolean'],
    blindCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli_blind/?id=1&Submit=Submit`, cookieParams: { security: 'low', PHPSESSID: SESSION }, config: { ...CFG_BASE, techniques: ['boolean'], enableExtract: true, extractScope: { blindDump: true }, dbms: 'MySQL', knownPoint: { param: 'id', quote: "'" }, testParameter: ['id'] } }),
    judge: (r) => ({ detected: techs(r.report).includes('boolean'), scalars: checkScalars(r.report) }),
  },
  {
    name: 'sqli_blind-medium',
    desc: 'POST id 数值型布尔（real_escape_string ⇒ 引号探针必死，不传 knownPoint）+ 盲注 opt-in',
    must: ['boolean'],
    blindCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli_blind/`, method: 'POST', bodyParams: { id: '1', Submit: 'Submit' }, cookieParams: { security: 'medium', PHPSESSID: SESSION }, config: { ...CFG_BASE, techniques: ['boolean'], enableExtract: true, extractScope: { blindDump: true }, dbms: 'MySQL', testParameter: ['id'] } }),
    judge: (r) => ({ detected: techs(r.report).includes('boolean'), scalars: checkScalars(r.report) }),
  },
  {
    name: 'sqli_blind-high',
    desc: 'COOKIE id 引号布尔（MISSING 404 + rand sleep）+ 盲注 opt-in（需 knownPoint 闭合）',
    must: ['boolean'],
    blindCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli_blind/?id=1&Submit=Submit`, cookieParams: { security: 'high', PHPSESSID: SESSION, id: '1' }, config: { ...CFG_BASE, techniques: ['boolean'], enableExtract: true, extractScope: { blindDump: true }, dbms: 'MySQL', knownPoint: { param: 'id', quote: "'" }, testParameter: ['id'] } }),
    judge: (r) => ({ detected: techs(r.report).includes('boolean'), scalars: checkScalars(r.report) }),
  },
  {
    name: 'sqli-impossible',
    desc: 'PDO prepare + is_numeric ⇒ 官方「不可利用」档（0 检出 + 打满预算）',
    must: [],
    safeCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli/?id=1&Submit=Submit`, cookieParams: { security: 'impossible', PHPSESSID: SESSION }, config: { ...CFG_BASE, validationSkip: false, testParameter: ['id'] } }),
    judge: (r) => ({ safe: techs(r.report).length === 0 && (r.report?.summary?.validity?.counts?.total ?? 0) >= SAFE_MIN_REQUESTS }),
  },
  {
    name: 'sqli_blind-impossible',
    desc: '盲注 PDO 档（0 检出 + 打满预算）',
    must: [],
    safeCheck: true,
    target: () => ({ url: `${BASE}/vulnerabilities/sqli_blind/?id=1&Submit=Submit`, cookieParams: { security: 'impossible', PHPSESSID: SESSION }, config: { ...CFG_BASE, validationSkip: false, testParameter: ['id'] } }),
    judge: (r) => ({ safe: techs(r.report).length === 0 && (r.report?.summary?.validity?.counts?.total ?? 0) >= SAFE_MIN_REQUESTS }),
  },
];

if (!(await reachable())) {
  console.log(`[SKIP] DVWA 不可达（${BASE}）—— 先 node scripts/labs.mjs --up=dvwa,mariadb`);
  process.exit(0);
}
console.log(`[all-levels] DVWA 就绪：${BASE}（官方源码 8 档真值 + 1 直驱拖库，非本仓断言）\n`);

const results = [];
for (const c of CASES) {
  const { report, status, elapsedMs } = await scanOnce(c.target());
  const found = techs(report);
  const j = c.judge({ report, must: c.must });
  const requests = report?.summary?.validity?.counts?.total ?? 0;

  // [D301] 两条 GAP 已修复并转硬判据：medium 拖库（--hex）、high 检测（diffJudge）
  // 都必须真实通过——不再有「PASS·GAP」容忍档。
  let ok;
  if (c.safeCheck) {
    ok = status === 'completed' && j.safe;
  } else if (c.blindCheck) {
    ok = status === 'completed' && j.detected && j.scalars.ok;
  } else {
    ok = status === 'completed' && j.detected && (!c.dumpCheck || j.dump.hits.length >= 4);
  }

  results.push({ name: c.name, desc: c.desc, status, elapsedMs, requests, found, must: c.must, ...j, ok });

  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${c.name}（${c.desc}）status=${status} 检出=[${found.join(',') || '-'}] 请求=${requests} 耗时=${(elapsedMs / 1000).toFixed(1)}s`);
  if (j.dump) {
    console.log(`       拖库：库=${JSON.stringify(j.dump.dbs)} 有行表=${JSON.stringify(j.dump.rowTables)}`);
    console.log(`       种子对账=${j.dump.hits.length}/5（${j.dump.hits.join('、') || '未命中'}）`);
  }
  if (j.scalars) {
    console.log(`       盲注标量=${JSON.stringify(j.scalars.scalars)} 通道=${JSON.stringify(j.scalars.channels)}`);
  }
}

// ── sqli-high：检测（[D301] diffJudge 布尔差异路径）+ 直驱二阶拖库（D300 能力本体）──
console.log(`\n── sqli-high：session 型二阶（官方 high.php）──`);
const highScan = await scanOnce({
  url: `${BASE}/vulnerabilities/sqli/session-input.php`,
  cookieParams: { security: 'high', PHPSESSID: SESSION },
  config: {
    // [真因修复] crawlForms：session-input.php 的表单点必须被发现（isStorePoint），否则
    // storePoints=[] ⇒ 二阶检测器零执行（supplementalRuns.js:35 的 filter）——此前 11 请求
    // 0.2s 的"检出=[]"根因是点没被发现，不是判定失效。
    ...CFG_BASE, crawlForms: true, techniques: ['error', 'boolean'], confirmFormWrites: true,
    // [D301] diffJudge：报错抑制形态（"Something went wrong."）签名判定不可见时的
    // 布尔差异判定（三重防误报：探针页/阴性页稳定性×2 + 差异存在性）
    secondOrder: { enabled: true, triggerUrls: [`${BASE}/vulnerabilities/sqli/`], negativeControl: true, diffJudge: true },
  },
});
const highFound = techs(highScan.report);
const highDetected = highFound.includes('second_order');
results.push({
  name: 'sqli-high-detection', desc: 'session 型二阶检测（签名 + [D301] 布尔差异双路径）',
  status: highScan.status, elapsedMs: highScan.elapsedMs,
  requests: highScan.report?.summary?.validity?.counts?.total ?? 0,
  found: highFound, must: ['second_order'], ok: highScan.status === 'completed' && highDetected,
});
console.log(`[${highDetected ? 'PASS' : 'FAIL'}] sqli-high 检测（session 型二阶，diffJudge=[D301]）status=${highScan.status} 检出=[${highFound.join(',') || '-'}] 请求=${highScan.report?.summary?.validity?.counts?.total ?? 0} 耗时=${(highScan.elapsedMs / 1000).toFixed(1)}s`);
if (highDetected) {
  const ev = (highScan.report?.vulns || []).find((v) => v.technique === 'second_order')?.evidence || '';
  console.log(`       证据：${String(ev).slice(0, 130)}`);
}

// 拖库直驱：存储点手工构造（session-input.php 表单是静态形态：POST id + Submit，无 CSRF token）
// ——不依赖检测扫描的点发现（预筛/爬取都可能让表单点缺席；官方源码即真值）。
const storePoint = {
  id: 'd300-store',
  location: 'body',
  param: 'id',
  actionUrl: `${BASE}/vulnerabilities/sqli/session-input.php`,
  formMethod: 'POST',
  formValues: { Submit: 'Submit' },
  originalValue: '1',
};
let dumpDirect = { ok: false };
try {
  const out = await directSecondOrderDump(storePoint, 'high');
  const rowText = JSON.stringify(out.rows || {});
  const hits = SEED_USERS.filter((u) => rowText.includes(u));
  const rowTables = Object.entries(out.rows || {}).filter(([, r]) => Array.isArray(r) && r.length > 0).map(([k, r]) => `${k}(${r.length}行)`);
  dumpDirect = { ok: out.dbs.length > 0 && hits.length >= 4, dbs: out.dbs, rowTables, hits };
  console.log(`[${dumpDirect.ok ? 'PASS' : 'FAIL'}] sqli-high 拖库直驱（D300 适配器语义：store→trigger + 串行 + 哨兵原值）`);
  console.log(`       库=${JSON.stringify(out.dbs)} 有行表=${JSON.stringify(rowTables)}`);
  console.log(`       种子对账=${hits.length}/5（${hits.join('、') || '未命中'}）`);
} catch (e) {
  console.log(`[FAIL] sqli-high 拖库直驱异常：${e.message}`);
}
results.push({
  name: 'sqli-high-dump-direct', desc: '直驱二阶拖库（MySQL 触发页：store→trigger、LIMIT 1 哨兵、串行）',
  ok: dumpDirect.ok, dbs: dumpDirect.dbs, rowTables: dumpDirect.rowTables, seedHits: dumpDirect.hits, status: 'completed',
});

const hardFails = results.filter((r) => !r.ok);
const passAll = hardFails.length === 0;
mkdirSync(RESULTS_DIR, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
writeFileSync(resolve(RESULTS_DIR, `all-levels-${stamp}.json`), JSON.stringify({ base: BASE, at: new Date().toISOString(), passAll, results }, null, 2));
const md = [
  `# DVWA 全模块 × 全等级真机验证 — ${new Date().toISOString()}`,
  '',
  `- 结论：**${passAll ? 'PASS' : 'FAIL'}**（硬失败 ${hardFails.length}）`,
  '',
  '| case | 结论 | 检出 | 关键判据 | 请求 | 耗时 |',
  '|---|---|---|---|---|---|',
  ...results.map((r) => `| ${r.name} | ${r.ok ? 'PASS' : 'FAIL'} | ${(r.found || []).join(',') || '-'} | ${r.dump ? `种子对账 ${r.dump.hits.length}/5` : r.scalars ? `标量 ${Object.values(r.scalars.scalars).filter(Boolean).length}/3` : r.seedHits ? `种子对账 ${r.seedHits.length}/5` : r.safe ? '0 检出+预算打满' : '-'} | ${r.requests ?? '-'} | ${r.elapsedMs ? (r.elapsedMs / 1000).toFixed(1) + 's' : '-'} |`),
  '',
  '> [D301] 原两条 GAP 已修复转硬判据：medium 拖库走 `--hex` 提取链（引号字面量全 0x 化），',
  '> sqli high 二阶检测走 `diffJudge` 布尔差异判定（三重防误报）——本表不再有容忍档。',
].join('\n');
writeFileSync(resolve(RESULTS_DIR, `all-levels-${stamp}.md`), md);
console.log(`\n[all-levels] 结果落盘 results/all-levels-${stamp}.{json,md}`);
console.log(passAll
  ? '✅ DVWA 全等级验证通过（含 --hex 拖库与 diffJudge 检测，硬失败 0）'
  : `❌ DVWA 全等级验证未通过（硬失败 ${hardFails.length}：${hardFails.map((r) => r.name).join('、')}）`);
process.exit(passAll ? 0 : 1);

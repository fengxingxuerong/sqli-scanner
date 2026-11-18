// ============================================================================
// e2e/real-world-lab/d300-so-dump.mjs —— [D300] 二阶拖库真机端到端验证（PGlite 拟真靶场）
//
// 链路：POST /comment 存 payload → GET /panel?id=1 触发页拼 SQL（SELECT * FROM items
// WHERE id=1 AND title != '<最新评论>'，5 列）→ extractPhaseD300 的二阶适配器把 Extractor
// 的每个 UNION 请求改写成 store→trigger 读回 → report.data 落行 + summary.d300Channels。
//
// 判据（诚实口径）：
//   1. second_order 命中（适配器前提）
//   2. data.databases 非空（触发页 UNION 枚举 information_schema 成功）
//   3. data.rows 至少一张表有行，行值与 PGlite 种子数据可对上（items 表标题）
//   4. summary.d300Channels 含 extended-extract；dumpUnconfirmed 须为空（真拖到了，不是空结果）
//   5. 并发强制串行生效：适配器共享「最新一条评论」状态，dump 期间靶场不得出现并发写竞争
// 结果落 results/d300-so-dump-<时间戳>.{json,md}
// 复跑：node e2e/real-world-lab/d300-so-dump.mjs
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRealLabApp } from './lab-app.js';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.REAL_LAB_PORT) || 8137; // 独立端口：不与 verify.mjs 的 8130 抢
const BASE = `http://127.0.0.1:${PORT}`;
const TIMEOUT_MS = Number(process.env.D300_SO_TIMEOUT_MS) || 420_000;

async function login(username, password) {
  const resp = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
    redirect: 'manual',
  });
  const sid = (resp.headers.get('set-cookie') || '').match(/sid=([^;]+)/)?.[1];
  if (!sid) throw new Error(`登录失败（${username}，status=${resp.status}）`);
  return sid;
}

const app = await createRealLabApp();
const server = app.listen(PORT, '127.0.0.1');
await new Promise((res, rej) => { server.once('listening', res); server.once('error', (e) => rej(new Error(`靶场监听失败: ${e.message}`))); });
const sm = new ScanManager();
const userSid = await login('alice', 'alice@example');
console.log(`[d300-so] 靶场就绪：${BASE}（PGlite，items 5 列）  sid=${userSid.slice(0, 8)}…`);

const out = await (async () => {
  const t0 = Date.now();
  const scanId = await sm.start({
    url: `${BASE}/`,
    cookieParams: { sid: userSid },
    config: {
      concurrency: 1,
      ratePerSec: 0,
      retry: 0,
      timeoutMs: 20000,
      productionMode: false,
      enableExtract: true,
      dbms: 'PostgreSQL', // 拟真靶场无报错指纹可用时 --dbms 强制（引擎 dbms 兜底链的最后一环）
      level: 5,
      crawlForms: true,
      confirmFormWrites: true,
      techniques: ['error', 'boolean'],
      // 触发页 = SELECT * FROM items（5 列）；回显列由 discoverEchoColumns 现场定位
      unionCols: '5',
      secondOrder: { enabled: true, triggerUrls: [`${BASE}/panel?id=1`], negativeControl: true },
    },
  });
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > TIMEOUT_MS) { sm.stop(scanId); return { status: 'timeout', elapsedMs: Date.now() - t0, report: null }; }
    await new Promise((r) => setTimeout(r, 200));
  }
  return { status: sm.scans.get(scanId)?.status || 'unknown', elapsedMs: Date.now() - t0, report: sm.getReport(scanId) || {} };
})();

const report = out.report || {};
const soVuln = (report.vulns || []).find((v) => v.technique === 'second_order');
const data = report.data || {};
const channels = report.summary?.d300Channels || [];
const rowEntries = Object.entries(data.rows || {}).filter(([, rows]) => Array.isArray(rows) && rows.length > 0);
const unconfirmed = data.meta?.dumpUnconfirmed || [];

// 种子对账：拖出来的 items 行里应能找到靶场种子标题（数据真伪，不只是「有行」）
const titles = ['九成新 iPad 9', '机械键盘 87 键', '人体工学椅', '《深入浅出 PostgreSQL》'];
const rowText = JSON.stringify(rowEntries.map(([, rows]) => rows));
const seedHits = titles.filter((t) => rowText.includes(t));

const checks = {
  soHit: Boolean(soVuln),
  dbsNonEmpty: Array.isArray(data.databases) && data.databases.length > 0,
  rowsNonEmpty: rowEntries.length > 0,
  seedDataMatch: seedHits.length >= 1,
  channelMarked: channels.includes('extended-extract'),
  noUnconfirmed: unconfirmed.length === 0,
};
const pass = Object.values(checks).every(Boolean);

console.log(`\n[${pass ? 'PASS' : 'FAIL'}] status=${out.status} 耗时=${(out.elapsedMs / 1000).toFixed(1)}s`);
console.log(`  second_order 命中=${checks.soHit}  库=${JSON.stringify(data.databases || [])}`);
console.log(`  有行表=${JSON.stringify(rowEntries.map(([k, rows]) => `${k}(${rows.length}行)`))}`);
console.log(`  种子对账=${seedHits.length}/4（${seedHits.join('、') || '未命中'}）  通道=${JSON.stringify(channels)}  dumpUnconfirmed=${JSON.stringify(unconfirmed)}`);
if (!checks.rowsNonEmpty && (report.summary?.constraints || []).length) {
  console.log(`  约束：${(report.summary.constraints || []).join(' | ')}`);
}

mkdirSync(RESULTS_DIR, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const payload = { base: BASE, at: new Date().toISOString(), pass, checks, out: { status: out.status, elapsedMs: out.elapsedMs }, dbs: data.databases || [], rowTables: rowEntries.map(([k, rows]) => ({ table: k, rows: rows.slice(0, 5) })), seedHits, channels, unconfirmed, requests: report.summary?.validity?.counts?.total ?? null };
writeFileSync(resolve(RESULTS_DIR, `d300-so-dump-${stamp}.json`), JSON.stringify(payload, null, 2));
writeFileSync(resolve(RESULTS_DIR, `d300-so-dump-${stamp}.md`), [
  `# D300 二阶拖库真机端到端（real-world-lab / PGlite）— ${new Date().toISOString()}`,
  '',
  `- 结论：**${pass ? 'PASS' : 'FAIL'}**  判据=${JSON.stringify(checks)}`,
  `- 库=${JSON.stringify(data.databases || [])}`,
  `- 有行表=${JSON.stringify(rowEntries.map(([k, rows]) => `${k}(${rows.length}行)`))}`,
  `- 种子对账 ${seedHits.length}/4：${seedHits.join('、') || '未命中'}`,
].join('\n'));
console.log(`\n[d300-so] 结果落盘 results/d300-so-dump-${stamp}.{json,md}`);
server.close();
process.exit(pass ? 0 : 1);

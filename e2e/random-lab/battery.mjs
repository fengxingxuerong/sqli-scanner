// ============================================================================
// e2e/random-lab/battery.mjs —— 随机化真值电池：用统计量支撑"检出率"
//
// 为什么要它：本仓所有检出率数字（13/13、19/19、10/10）都来自**手搓靶点**。手搓有两重偏见：
//   ① 作者知道哪里是洞，靶点会不长得"像检测器已经会认的那些形态"；
//   ② 样本太小 —— 13/13 的 95% 置信区间下界只有 ~80%，把它当"检出率 100%"是数字滥用。
// 这里改成：同一个种子能复现地**生成**一批案例（注入点上下文 × SQL 形态 × 良性对照随机组合），
// 每个案例带 ground truth，跑完报 召回 / 精确 / **Wilson 95% 置信区间**，而不是一个分数。
//
// 用法：
//   node e2e/random-lab/battery.mjs                     # 默认 24 例（12 注入 + 12 良性），seed 随机
//   node e2e/random-lab/battery.mjs --seed=20260919 --cases=40
//   MYSQL_PORT=3308 node e2e/random-lab/battery.mjs     # 配 e2e/run-with-sandbox.py 用
// 退出码：召回率 CI 下界 < 门槛 或 有良性误报 → 1。
//   （报的是区间下界而不是点估计 —— 逼自己承认样本量。）
// ============================================================================
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const require = createRequire(pathToFileURL(resolve(ROOT, 'server/package.json')).href);
const mysql = require('mysql2/promise');
const express = require('express');
// 扫的是本电池自己在 127.0.0.1 起的靶场，SSRF 私网守卫必须放行（其它靶场由 run-all / .env.test 提供）。
// 必须**在 import 引擎之前**设：引擎在模块加载时读一次这个开关。
process.env.SSRF_ALLOW_PRIVATE = process.env.SSRF_ALLOW_PRIVATE || '1';
const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
// 回显剥离：ground truth 自证必须用它，否则"页面把 payload 原样打回来"会让真假两个响应
// 天然不同，把根本不可观测的案例算进分母（本仓在检测链路上已经为这件事栽过四次）。
const { stripEchoedPayload } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/echoStrip.js')).href);

const arg = (k, d) => {
  const a = process.argv.find((x) => x.startsWith(`--${k}=`));
  return a ? a.slice(k.length + 3) : d;
};
const SEED = Number(arg('seed', String(Date.now() % 1e9)));
const CASES = Number(arg('cases', '24'));
const PORT = Number(arg('port', '8291'));
const RECALL_FLOOR = Number(arg('recall-floor', '70')); // 百分点；CI 下界低于此判红
const MYSQL = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};

// —— 可复现随机（mulberry32）：种子即结果，别人能重跑同一批案例 ——
let _s = SEED >>> 0;
const rnd = () => {
  _s = (_s + 0x6d2b79f5) >>> 0;
  let t = _s;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (a) => a[Math.floor(rnd() * a.length)];
const int = (n) => Math.floor(rnd() * n);

// —— 案例模板 ——
// 注入形态：SQL 文本里**直接拼**参数值（真实漏洞的形状），need = 该上下文需要的闭合前缀
const VULN_SHAPES = [
  { key: 'num', sql: (v) => `SELECT ${cols} FROM ${TBL} WHERE id=${v}`, need: '' },
  { key: 'str', sql: (v) => `SELECT ${cols} FROM ${TBL} WHERE name='${v}'`, need: "'" },
  { key: 'like', sql: (v) => `SELECT ${cols} FROM ${TBL} WHERE name LIKE '%${v}%'`, need: "%'" },
  { key: 'paren', sql: (v) => `SELECT ${cols} FROM ${TBL} WHERE id=(${v})`, need: ')' },
  { key: 'strparen', sql: (v) => `SELECT ${cols} FROM ${TBL} WHERE name=('${v}')`, need: "')" },
  { key: 'orderby', sql: (v) => `SELECT ${cols} FROM ${TBL} ORDER BY ${v}`, need: '' },
];
// 良性形态：同一个参数值，但 SQL 是**参数化/白名单/强转/转义**出来的 —— 结构上不可能被注入。
// 这是测误报的地方：检测器只要报一个就是真误报，没有"也许靶点没写好"的退路。
const SAFE_SHAPES = [
  { key: 'param', run: (v, p) => p.query(`SELECT ${cols} FROM ${TBL} WHERE id=?`, [Number(v) || 1]) },
  { key: 'intval', run: (v, p) => p.query(`SELECT ${cols} FROM ${TBL} WHERE id=${Number.isFinite(+v) ? Math.trunc(+v) : 1}`) },
  { key: 'whitelist', run: (v, p) => p.query(`SELECT ${cols} FROM ${TBL} ORDER BY ${{ id: 'id', name: 'name', price: 'price', category: 'category' }[v] ?? 'id'}`) },
  { key: 'escape', run: (v, p) => p.query(`SELECT ${cols} FROM ${TBL} WHERE name=${p.escape(String(v))}`) },
];
// 原始值必须**真的能命中行**，否则真假探针都是空集 → 案例按构造不可观测（先前用了 'key'/'mouse'
// 这种不在数据里的词，12/12 全被自证剔掉，分母直接空了）。
const VALUES = {
  num: ['1', '2'],
  str: ['Mechanical Keyboard', 'USB-C Hub'],
  like: ['Key', 'Hub', 'board'],
  paren: ['1', '2'],
  strparen: ['Notebook', 'USB-C Hub'],
  orderby: ['id', 'name', 'price'],
};
const PARAM_NAMES = ['id', 'q', 'keyword', 'sort', 'pid', 'ref'];

/** 生成一批案例：一半注入一半良性，随机形态 + 随机参数名 + 随机原始值。 */
function buildCases(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const vulnerable = i % 2 === 0;
    const shape = vulnerable ? pick(VULN_SHAPES) : pick(SAFE_SHAPES);
    const param = shape.key === 'orderby' ? 'sort' : pick(vulnerable ? PARAM_NAMES : ['id', 'sort', 'name']);
    const base = vulnerable
      ? pick(VALUES[shape.key] ?? ['1'])
      : shape.key === 'escape'
        ? pick(VALUES.str)
        : shape.key === 'whitelist'
          ? pick(['id', 'name', 'price'])
          : String(1 + int(2));
    out.push({
      id: `c${String(i).padStart(2, '0')}-${shape.key}`,
      vulnerable,
      shape: shape.key,
      param,
      value: base,
      need: vulnerable ? shape.need : null,
      sqlOf: vulnerable ? shape.sql : null,
      safeRun: vulnerable ? null : shape.run,
    });
  }
  return out;
}

// —— 靶场表与连接（必须在 buildCases 之前声明：模板字符串引用 TBL/cols）——
// 自建表，不借用其它靶场的 schema：先前直接写 `products(name,price)`，在真 MySQL 上报
// "Unknown column 'name' in 'field list'" —— 别人的表长什么样不是本电池能假设的事。
const TBL = 'randlab_products';
const cols = 'id,name,price,category';
const pool = mysql.createPool({ ...MYSQL, connectionLimit: 6, multipleStatements: true });
async function setupSchema() {
  await pool.query(`DROP TABLE IF EXISTS ${TBL}`);
  await pool.query(`CREATE TABLE ${TBL} (id INT PRIMARY KEY, name VARCHAR(64), price DECIMAL(10,2), category VARCHAR(32))`);
  await pool.query(
    `INSERT INTO ${TBL} (id,name,price,category) VALUES (1,'Mechanical Keyboard',399.00,'electronics'),(2,'USB-C Hub',129.00,'electronics'),(3,'Notebook',29.00,'stationery')`
  );
}

const cases = buildCases(CASES);
const app = express();
app.use(express.urlencoded({ extended: false }));
// 一条路由抛出去不能带走整批：本电池要的是统计量，个别案例测不到就记成 error 继续跑。
process.on('unhandledRejection', (e) => console.log(`  [靶场异步异常，已吞] ${String(e && e.message || e).slice(0, 120)}`));
for (const c of cases) {
  app.get(`/r/${c.id}`, async (req, res) => {
    const v = String(req.query[c.param] ?? c.value);
    try {
      // 取结果要防两种形态：mysql2 的 [rows, fields]，以及（多语句/无结果集时）直接给包对象。
      // 原来写 `(await pool.query(q))[0]` 再 JSON.stringify(rows).slice(...) —— 当它是 undefined 时
      // JSON.stringify 返回 undefined，.slice 抛 TypeError → 路由回 500。后果很阴：
      // 真/假两个探针**都**变成同一张 500 页，于是"按构造不可观测"的自证把它们全剔除，
      // 分母直接归零，看起来像靶场没洞。（这一轮就在这里绕了三圈。）
      const raw = c.vulnerable ? await pool.query(c.sqlOf(v)) : await c.safeRun(v, pool);
      const rows = Array.isArray(raw) ? (raw[0] ?? []) : raw;
      const body = JSON.stringify(rows ?? null).slice(0, 4000);
      res.status(200).send(`<html><body><h1>Catalog</h1><pre>${body}</pre><p>param ${c.param}=${escapeHtml(v)}</p></body></html>`);
    } catch (e) {
      const detail = process.env.BATTERY_DEBUG ? String(e?.stack || '').split('\n').slice(0, 4).join(' | ') : String(e?.message || e);
      try {
        res.status(500).send(`<html><body><p>Error: ${escapeHtml(detail).slice(0, 400)}</p></body></html>`);
      } catch { /* 响应已发出，忽略 */ }
    }
  });
}
const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));

// Wilson 区间：小样本下比"正态近似"诚实（13/13 的点估计是 100%，下界只有 ~80%）
function wilson(k, n, z = 1.96) {
  if (!n) return [0, 0];
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const s = z * Math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n);
  return [((c - s) / d) * 100, ((c + s) / d) * 100];
}

/**
 * ground truth 自证：对"注入"案例先自己发一对**已知真假**的探针，只有响应确实不同才算
 * "可观测的漏洞"。不做这一步，分母里就会混进按构造不可能被任何检测器发现的案例 ——
 * 例：ORDER BY name AND 1=1 / AND 1=2 行序完全一样；LIKE '%mouse%' 两边都零行。
 * 那类案例算进"漏报"是让电池自己骗自己。剔除后单列成 unobservable，报告里如实写明。
 */
const PROBE_PAIRS = {
  '': [' AND 1=1-- -', ' AND 1=2-- -'],
  "'": ["' AND 1=1-- -", "' AND 1=2-- -"],
  "%'": ["%' AND 1=1-- -", "%' AND 1=2-- -"],
  ')': [') AND 1=1-- -', ') AND 1=2-- -'],
  "')": ["') AND 1=1-- -", "') AND 1=2-- -"],
};
async function observable(c) {
  const pair = PROBE_PAIRS[c.need] ?? PROBE_PAIRS[''];
  const get = async (suffix) => {
    const v = c.value + suffix;
    const url = `${BASE}/r/${c.id}?${c.param}=${encodeURIComponent(v)}`;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
      // **必须剥掉页面里回显的那份 payload** 再比较：靶场会把参数值原样打在页面上
      // （`param sort=name AND 1=1-- -`），于是真假两个响应的字节必然不同 —— 拿原始 body
      // 比会把"根本不可观测"的案例误判成可观测，等于给分母掺假。本仓对这件事的教训已经
      // 有四个实例（见 server/src/engine/echoStrip.js 文件头），这里不能当第五个。
      const body = stripEchoedPayload(await res.text(), v);
      return `${res.status}|${body}`;
    } catch (e) {
      if (process.env.BATTERY_DEBUG) console.log(`      [gt-dbg] fetch 抛错 ${e.name}: ${String(e.cause?.message || e.message).slice(0, 90)}`);
      return null;
    }
  };
  const t = await get(pair[0]);
  const f = await get(pair[1]);
  if (process.env.BATTERY_DEBUG) {
    console.log(`      [gt-dbg] ${c.id} need=${JSON.stringify(c.need)} pair=${JSON.stringify(pair)} 真长=${t ? t.length : 'null'} 假长=${f ? f.length : 'null'} 相同=${t === f}`);
    if (t && f && t === f) console.log(`      [gt-dbg] 剥回显后一致，内容前 120：${t.slice(0, 120)}`);
  }
  return !!t && !!f && t !== f;
}

const server = app.listen(PORT, '127.0.0.1');
await new Promise((res, rej) => { server.once('listening', res); server.once('error', (e) => rej(new Error(`靶场监听失败：${e.message}`))); });
const BASE = `http://127.0.0.1:${PORT}`;

const sm = new ScanManager();
await setupSchema(); // 自建表（跑完 DROP），不假设任何既有靶场的 schema
const cfg = { concurrency: 1, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false, level: 3, risk: 1 };
const runOne = async (url) => {
  const t0 = Date.now();
  const scanId = await sm.start({ url, config: cfg });
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 150000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [] }; }
    await new Promise((r) => setTimeout(r, 50));
  }
  const rep = sm.getReport(scanId) || {};
  if (process.env.BATTERY_DEBUG) {
    // 排障用：要看清是"没发现注入点"还是"发现了但判据不过"——两者的修法完全相反
    console.log(`    [dbg] ${url} points=${(rep.points || []).length} reqs=${rep.summary?.requests ?? '?'} vulns=${(rep.vulns || []).length} 状态=${rep.status || '?'}`);
    for (const p of (rep.points || []).slice(0, 4)) console.log(`      [dbg] 点 ${p.param}@${p.location} confirmed=${p.confirmed} boundary=${JSON.stringify(p.boundary)} dbms=${p.dbms}`);
    if (rep.summary?.constraints?.length) console.log(`      [dbg] constraints=${JSON.stringify(rep.summary.constraints)}`);
  }
  return { status: 'done', vulns: rep.vulns || [] };
};

console.log(`=== 随机化真值电池：seed=${SEED} 案例=${cases.length}（注入 ${cases.filter((c) => c.vulnerable).length} / 良性 ${cases.filter((c) => !c.vulnerable).length}）===`);
console.log(`目标 MySQL ${MYSQL.host}:${MYSQL.port}/${MYSQL.database}；检测口径 level=3 risk=1 全技术 串行\n`);

const results = [];
for (const c of cases) {
  const url = `${BASE}/r/${c.id}?${c.param}=${encodeURIComponent(c.value)}`;
  let unobservable = false;
  if (c.vulnerable) {
    unobservable = !(await observable(c));
    if (unobservable) {
      // 连"真 vs 假"都不改变响应 —— 任何检测器都不可能发现，剔出召回分母，单列
      results.push({ id: c.id, shape: c.shape, vulnerable: true, detected: false, status: 'unobservable', techs: [], dbms: [] });
      console.log(`  – 按构造不可观测（剔出分母）  ${c.id.padEnd(16)} ${c.shape}`);
      continue;
    }
  }
  const r = await runOne(url);
  const detected = r.vulns.length > 0;
  results.push({ id: c.id, shape: c.shape, vulnerable: c.vulnerable, detected, status: r.status, techs: [...new Set(r.vulns.map((v) => v.technique))], dbms: [...new Set(r.vulns.map((v) => String(v.dbms)))] });
  console.log(`  ${c.vulnerable ? (detected ? '✓ 召回' : '✗ 漏报') : detected ? '✗ 误报' : '✓ 正确放行'}  ${c.id.padEnd(16)} ${String(r.status).padEnd(8)} [${results[results.length - 1].techs.join(',') || '-'}]`);
}

const unobs = results.filter((x) => x.status === 'unobservable');
const P = results.filter((x) => x.vulnerable && x.status !== 'unobservable');
const N = results.filter((x) => !x.vulnerable);
const recallOk = P.filter((x) => x.detected).length;
const fpCount = N.filter((x) => x.detected).length;
const [rl] = wilson(recallOk, P.length);
const precision = P.filter((x) => x.detected).length + fpCount ? (P.filter((x) => x.detected).length / (P.filter((x) => x.detected).length + fpCount)) * 100 : 100;

console.log('\n=== 统计（不是点估计，给区间）===');
if (unobs.length) console.log(`  另有 ${unobs.length} 个"按构造不可观测"的注入案例已剔出分母（形态：${[...new Set(unobs.map((x) => x.shape))].join(', ')}）`);
console.log(`  召回率 ${recallOk}/${P.length} = ${(P.length ? (recallOk / P.length) * 100 : 0).toFixed(1)}%　Wilson 95%CI 下界 ${rl.toFixed(1)}%`);
console.log(`  误报 ${fpCount}/${N.length} 良性案例　精确率 ${precision.toFixed(1)}%`);
const missBy = {};
for (const x of P.filter((y) => !y.detected)) missBy[x.shape] = (missBy[x.shape] || 0) + 1;
if (Object.keys(missBy).length) console.log(`  漏报按形态：${Object.entries(missBy).map(([k, v]) => `${k}:${v}`).join('  ')}`);
const fpBy = {};
for (const x of N.filter((y) => y.detected)) fpBy[x.shape] = (fpBy[x.shape] || 0) + 1;
if (Object.keys(fpBy).length) console.log(`  误报按形态：${Object.entries(fpBy).map(([k, v]) => `${k}:${v}`).join('  ')}`);

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(
  resolve(HERE, 'results', 'battery.json'),
  JSON.stringify({ at: new Date().toISOString(), seed: SEED, cases: cases.length, mysql: `${MYSQL.host}:${MYSQL.port}`, unobservable: unobs.map((x) => x.id), recall: { hit: recallOk, total: P.length, ci95Lower: +rl.toFixed(2) }, falsePositive: { count: fpCount, total: N.length, byShape: fpBy }, missByShape: missBy, results }, null, 2)
);
console.log(`\n[report] e2e/random-lab/results/battery.json（换 seed 重跑即可，例：--seed=${SEED + 1}）`);
// 历史累计：单轮 JSON 会被下一轮覆盖，而"跑过几轮、总共多少样本"正是这类统计量必须回答的问题。
// 每轮追加一行（jsonl），门禁与文档都据此报"跨 N 轮、共 M 例"。
{
  const { appendFileSync } = await import('node:fs');
  appendFileSync(
    resolve(HERE, 'results', 'battery-history.jsonl'),
    JSON.stringify({ at: new Date().toISOString(), seed: SEED, requested: cases.length, observableVuln: P.length, unobservable: unobs.length, recallHit: recallOk, benign: N.length, fp: fpCount, ci95Lower: +rl.toFixed(2) }) + '\n'
  );
}

server.close();
await pool.query(`DROP TABLE IF EXISTS ${TBL}`).catch(() => {}); // 自建表自建于此，跑完清干净
await pool.end().catch(() => {});
const bad = rl < RECALL_FLOOR || fpCount > 0;
console.log(bad ? `\n❌ 召回 CI 下界 ${rl.toFixed(1)}% < ${RECALL_FLOOR}% 或存在误报（${fpCount}）` : `\n✅ 召回 CI 下界 ${rl.toFixed(1)}% ≥ ${RECALL_FLOOR}%，且良性案例零误报`);
process.exit(bad ? 1 : 0);

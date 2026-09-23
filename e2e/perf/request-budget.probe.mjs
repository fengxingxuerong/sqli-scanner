#!/usr/bin/env node
// ============================================================================
// request-budget.probe.mjs —— 「一次扫描到底发了多少请求」离线计数探针
//
// 为什么需要它（2026-09-23 优化勘查 §C）：
// 勘查报告里那批性能结论（各检测器各自重发基线 / 回显列定位不缓存 / 二分每步重发假基准）
// 全是**静态推断**，没有一条有真实请求数。本项目纪律是「先量再改」——
// 拿直觉调参等于把优化变成赌博。本探针把它们变成可复跑的数字。
//
// 为什么不需要靶场：所有检测器最终都收敛到 `httpClient.request(opts)`
// （见 engine/Detector.js:660 `send()`）。用一个**记录型 stub** 顶替 httpClient，
// 就能在无网络、无服务、无 DB 的前提下精确数出请求数与重复数。
//
// 口径（重要，别误读）：
//   · 目标设为**安全点**（所有探测都不命中）—— 这是真实扫描里绝大多数点的形态，
//     也是请求浪费最容易被看见的场景。
//   · 测的是**检测阶段**，不含提取(extract)阶段与 WAF 重跑路径（后者需真靶场）。
//   · time/stacked/oob 三个慢通道**未采样**（time 会真 sleep，数分钟级）。
//
// 跑法：node e2e/perf/request-budget.probe.mjs
// ============================================================================

import { UnionDetector } from '../../server/src/engine/detectors/UnionDetector.js';
import { ErrorDetector } from '../../server/src/engine/detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../../server/src/engine/detectors/BooleanBlindDetector.js';
import { InlineQueryDetector } from '../../server/src/engine/detectors/InlineQueryDetector.js';
import { NoSqlInjectionDetector } from '../../server/src/engine/detectors/NoSqlInjectionDetector.js';

// ── 记录型 httpClient ──────────────────────────────────────────────────────
// 安全点响应：始终返回同一份正常页面 → 所有通道都判「未命中」→ 走完整探测流程。
const SAFE_BODY = '<html><body><table><tr><td>normal row</td></tr></table></body></html>';

function fingerprint(o) {
  const headers = o.headers
    ? JSON.stringify(Object.keys(o.headers).sort().map((k) => [k, o.headers[k]]))
    : '';
  const data = o.data === undefined || o.data === null ? '' : JSON.stringify(o.data);
  return `${(o.method || 'GET').toUpperCase()} ${o.url || ''} | ${data} | ${headers}`;
}

function createProbeClient() {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push({ fp: fingerprint(opts), opts });
      return { status: 200, data: SAFE_BODY, headers: {} };
    },
    // 少数路径可能直接调 get/post 之类；缺失时报错更诚实，别静默吞掉
    async get(url, o) { return this.request({ ...(o || {}), method: 'GET', url }); },
    async post(url, o) { return this.request({ ...(o || {}), method: 'POST', url }); },
  };
}

// ── payload 形态归因 ───────────────────────────────────────────────────────
// 光知道「发了 148 条」不够，要知道**花在哪**才谈得上优化。
// 规则有序匹配（先具体后宽泛），只用于归因展示，不参与任何判定。
function payloadOf(o) {
  const url = String(o.url || '');
  const m = url.match(/[?&]q=([^&]*)/);
  if (m) {
    try { return decodeURIComponent(m[1]).replace(/\+/g, ' '); } catch { return m[1]; }
  }
  if (o.data && typeof o.data === 'object' && o.data.q !== undefined) return String(o.data.q);
  if (o.data && typeof o.data === 'string' && /(^|&)q=/.test(o.data)) {
    const mm = o.data.match(/(^|&)q=([^&]*)/);
    if (mm) { try { return decodeURIComponent(mm[2]); } catch { return mm[2]; } }
  }
  const hdrs = o.headers || {};
  for (const [k, v] of Object.entries(hdrs)) {
    if (k.toLowerCase() === 'cookie') {
      const cm = String(v).match(/q=([^;]*)/);
      if (cm) return cm[1];
      continue;
    }
    if (typeof v === 'string') return v;
  }
  return '';
}

function classify(o) {
  const p = payloadOf(o);
  if (p === '1' || p === '') return '① 原值基线（q=1）';
  if (/ORDER BY \d+/i.test(p)) return '② ORDER BY 列数探测';
  if (/UNION\s+(?:ALL\s+)?SELECT/i.test(p)) return '③ UNION SELECT 试探';
  if (/AND\s+1\s*=\s*[12]|OR\s+1\s*=\s*[12]|'1'\s*=\s*'[12]'|1=1|1=2/i.test(p)) return '④ 布尔真假对';
  if (/extractvalue|updatexml|exp\s*\(|geometrycollection|polygon|multipoint|dbms_pipe|utl_inaddr|utl_http|convert\s*\(|cast\s*\(|ctxsys|xmltype|to_char|ERROR|EXCEPTION|invalid/i.test(p)) return '⑤ 报错类 payload';
  if (/SLEEP|pg_sleep|WAITFOR|BENCHMARK|heavy|randomblob/i.test(p)) return '⑥ 时间类 payload';
  if (/information_schema|sys\.|sysobjects|all_tables|pg_catalog/i.test(p)) return '⑦ 元数据读取';
  if (p === '1%' || /LIKE/i.test(p)) return '⑧ LIKE/模糊类';
  return '⑨ 其他变体';
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock.local/items?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      timeThresholdMs: 800,
      level: 1,
      risk: 1,
      techniques: ['union', 'error', 'boolean', 'inline', 'nosql'],
      useRegistry: false,
      // 关掉所有"会额外发请求"的可选项，得到**最小配置**下的请求预算
      prefilter: false,
      unionSkipGate: true,
    },
    ...overrides,
  };
}

// ── 逐检测器计数 ───────────────────────────────────────────────────────────
const DETECTORS = [
  ['union', UnionDetector],
  ['error', ErrorDetector],
  ['boolean', BooleanBlindDetector],
  ['inline', InlineQueryDetector],
  ['nosql', NoSqlInjectionDetector],
];

const rows = [];
/** 跨检测器共享的"重复指纹"账本：fp → [{ detector, seq }] */
const globalSeen = new Map();
/** 全局 payload 形态归因 */
const globalKind = new Map();

for (const [name, Ctor] of DETECTORS) {
  const client = createProbeClient();
  const det = new Ctor();
  const t0 = Date.now();
  let err = null;
  try {
    await det.detect(buildCtx(client));
  } catch (e) {
    err = e.message;
  }
  const ms = Date.now() - t0;

  const localCounts = new Map();
  const kindCounts = new Map();
  for (const c of client.calls) {
    localCounts.set(c.fp, (localCounts.get(c.fp) || 0) + 1);
    if (!globalSeen.has(c.fp)) globalSeen.set(c.fp, []);
    globalSeen.get(c.fp).push(name);
    const kind = classify(c.opts);
    kindCounts.set(kind, (kindCounts.get(kind) || 0) + 1);
    globalKind.set(kind, (globalKind.get(kind) || 0) + 1);
  }
  const dupWithin = [...localCounts.values()].filter((n) => n > 1).reduce((s, n) => s + (n - 1), 0);

  rows.push({
    name,
    total: client.calls.length,
    unique: localCounts.size,
    dupWithin,
    ms,
    err,
    kindCounts,
  });
}

// ── 输出 ───────────────────────────────────────────────────────────────────
const pad = (s, n) => String(s).padEnd(n);
const num = (s, n) => String(s).padStart(n);

console.log('=== 单点检测请求预算（安全点 / 最小配置 / 不含 time·stacked·oob）===');
console.log(`${pad('检测器', 10)}${num('请求数', 8)}${num('唯一', 7)}${num('自身重复', 10)}${num('耗时ms', 9)}  备注`);
console.log('-'.repeat(64));
for (const r of rows) {
  console.log(
    `${pad(r.name, 10)}${num(r.total, 8)}${num(r.unique, 7)}${num(r.dupWithin, 10)}${num(r.ms, 9)}  ${r.err ? 'ERR: ' + r.err : ''}`
  );
}
const totalReq = rows.reduce((s, r) => s + r.total, 0);
const totalDup = rows.reduce((s, r) => s + r.dupWithin, 0);
console.log('-'.repeat(64));
console.log(`${pad('合计', 10)}${num(totalReq, 8)}${num('', 7)}${num(totalDup, 10)}`);

// ── payload 形态归因 ───────────────────────────────────────────────────────
console.log('');
console.log('=== 请求花在哪（按注入值形态，合计）===');
const kindRanked = [...globalKind.entries()].sort((a, b) => b[1] - a[1]);
for (const [kind, n] of kindRanked) {
  const pct = ((n / totalReq) * 100).toFixed(1);
  console.log(`  ${String(n).padStart(4)} 条 (${String(pct).padStart(5)}%)  ${kind}`);
}
console.log('');
console.log('  分检测器明细（仅列该检测器发过的形态）：');
for (const r of rows) {
  const parts = [...r.kindCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k.replace(/^[①②③④⑤⑥⑦⑧⑨]\s*/, '')}=${n}`);
  console.log(`    ${pad(r.name, 8)} ${parts.join('  ')}`);
}

// ── 跨检测器重复（这是 §C1 的直接量化）────────────────────────────────────
const crossDup = [...globalSeen.entries()]
  .filter(([, who]) => new Set(who).size > 1)
  .map(([fp, who]) => ({ fp, n: who.length, who: [...new Set(who)] }))
  .sort((a, b) => b.n - a.n);

console.log('');
console.log(`=== 跨检测器「字节级完全相同」的请求：${crossDup.length} 条 ===`);
if (crossDup.length) {
  console.log('（同一份请求被 N 个检测器各发一次 → C1「共享基线未被复用」的直接证据）');
  for (const d of crossDup.slice(0, 12)) {
    console.log(`  ×${d.n}  [${d.who.join(', ')}]  ${d.fp.slice(0, 110)}`);
  }
  if (crossDup.length > 12) console.log(`  … 另有 ${crossDup.length - 12} 条`);
  const wasted = crossDup.reduce((s, d) => s + (d.n - 1), 0);
  console.log('');
  console.log(`可省请求（上界估计）= 跨检测器重复的冗余份数 = ${wasted} / ${totalReq}`
    + `（${((wasted / totalReq) * 100).toFixed(1)}%）`);
  console.log('⚠️ 这是**上界**：只有「同一份请求的响应可被复用」时才真的能省。');
  console.log('   判定可复用需先证各检测器要的 baseline 语义等价（见 docs 勘查 §C1 的待验证项）。');
} else {
  console.log('  未发现跨检测器完全相同的请求。');
}

console.log('');
console.log('=== 未采样通道（本探针不覆盖，别当成「无浪费」）===');
console.log('  · time / stacked / oob —— 会真 sleep 或需真靶场');
console.log('  · 提取(extract)阶段 —— 需真实 DB 回显（§C2 回显列定位重复的战场）');
console.log('  · WAF 自适应重跑路径 —— 需真被拦截（§C1 提到的 +40~60 请求/点）');
console.log('  · 请求数会随 config.level/risk 与目标响应形态变化；本表是「最小配置 + 安全点」下的下界');

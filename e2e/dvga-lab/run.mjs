// ============================================================================
// e2e/dvga-lab/run.mjs —— [D114 2026-10-20 → D121 2026-10-21] GraphQL 面外部裁判：DVGA（Flask + SQLite）
//
// ── 为什么还要第三个外部靶场 ───────────────────────────────────────────────
// 外部裁判此前只有 Juice Shop（query + JSON 字段）与 VAmPI（URL 路径段）。
// **GraphQL 是真实 API 里增长最快的一类面**，而它的注入形态与前两者都不同：
// 注入点不在 query string、不在路径段，而在 **POST body 里那段 GraphQL 查询字符串的
// 内部**（`{ pastes(filter: "…") { … } }`）—— 值替换必须同时保持 GraphQL 语法合法。
// DVGA（dolevf/Damn-Vulnerable-GraphQL-Application，故意脆弱 GraphQL 应用）官方自带
// SQLi 挑战，真值来自 `core/views.py` 的字符串拼接，非本仓断言。
//
// ── 真值（外部源码，非本仓编写）─────────────────────────────────────────────
// `core/views.py:resolve_pastes`：
//   if filter:
//     result = result.filter(text("title = '%s' or content = '%s'" % (filter, filter)))
// 实机（手工复核）：
//   filter "x"                → {"data":{"pastes":[]}}
//   filter "x' OR 1=1-- -"    → 返回全部 pastes（布尔真）
//   filter "x' OR 1=2-- -"    → []                      ⇒ 布尔可分
//
// ── D121 结论（2026-10-21）──────────────────────────────────────────────────
// 新增 GraphQL 查询串内联字面量点后，真值点 `pastes(filter)` **1/1**（union/error/
// boolean 三通道命中）；安全点 `search(keyword)` 0 误报（124 请求）；无 filter 的
// resolver 因没有字符串字面量而**0 点/0 请求**（结构对照，不计检出证据）。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要 DVGA 已构建并运行（见同目录 README.md）。未就绪时输出 `[SKIP]` 并以 **exit 0**
// 退出 —— 与 juice-shop-lab / vampi-lab 同口径：环境缺失不该让门禁红，但也**不计入通过**。
//
// 复跑：DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const BASE = process.env.DVGA_BASE || 'http://127.0.0.1:5013';
const TIMEOUT_MS = Number(process.env.DVGA_LAB_TIMEOUT_MS) || 200000;

/** 端点清单：真漏洞端点（必须检出）与安全端点（必须零误报） */
const ENDPOINTS = [
  {
    path: '/graphql',
    method: 'POST',
    jsonBody: { query: '{ pastes(public: true, filter: "x") { id title } }' },
    kind: 'vuln',
    desc: 'GraphQL pastes(filter) —— 官方 views.py:320 字符串拼接（注入点在 GraphQL 查询串内部）',
  },
  {
    // 安全对照 1：同一 resolver 不带 filter ⇒ 走 ORM，无拼接
    path: '/graphql',
    method: 'POST',
    jsonBody: { query: '{ pastes(public: true) { id title } }' },
    kind: 'safe',
    minRequests: 0,
    desc: '同 resolver 不带 filter（无字符串字面量 ⇒ 预期 0 点/0 请求，结构对照不计证据）',
  },
  {
    // 安全对照 2：官方 resolve_search 用 `like(search)` 参数化（`%{}%`.format，值走绑定参数）
    path: '/graphql',
    method: 'POST',
    jsonBody: { query: '{ search(keyword: "x") { __typename } }' },
    kind: 'safe',
    desc: 'search(keyword) —— ORM like 参数化',
  },
];

const SCAN_CFG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 12000,
  techniques: ['union', 'boolean', 'error', 'time'],
  enableExtract: false,
  level: 2,
  risk: 2,
  productionMode: false,
};

async function reachable() {
  try {
    const r = await fetch(`${BASE}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ pastes(public: true) { id title } }' }),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return false;
    const j = await r.json().catch(() => null);
    // 必须是 DVGA 形态（GraphQL data 信封），避免把别的服务误当靶场
    return !!(j && j.data && Array.isArray(j.data.pastes));
  } catch {
    return false;
  }
}

async function scanOne(ep) {
  const sm = new ScanManager({});
  const target = { url: `${BASE}${ep.path}`, config: { ...SCAN_CFG } };
  if (ep.method) target.method = ep.method;
  if (ep.jsonBody) target.jsonBody = { ...ep.jsonBody };
  const id = await sm.start(target);
  const t0 = Date.now();
  for (;;) {
    const st = sm.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) {
      const rep = sm.getReport(id) || {};
      const counts = rep.summary?.validity?.counts || {};
      const vs = rep.vulns || [];
      return {
        vulns: vs.length,
        techniques: vs.map((v) => v.technique || v.vulnType?.nameEn || '?'),
        detail: vs.map((v) => {
          const p = v.point || {};
          return `${p.location || v.location || '?'}·${p.param || v.param || '?'}·dbms=${v.dbms || rep.summary?.dbmsEvidence?.dbms || '?'}`;
        }),
        requests: counts.total || 0,
        verdict: rep.summary?.verdict || '-',
      };
    }
    if (Date.now() - t0 > TIMEOUT_MS) {
      sm.stop(id);
      return { vulns: -1, techniques: [], detail: [], requests: 0, verdict: 'timeout' };
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

if (!(await reachable())) {
  console.log(`[SKIP] DVGA 靶场不可达（${BASE}）—— 需先构建并启动，跳过（不计通过亦不计失败）`);
  console.log('       构建与启动见 e2e/dvga-lab/README.md（codeload tarball → venv 装依赖 →');
  console.log('       手动 python setup.py 建库 → WEB_PORT=5013 python app.py）');
  process.exit(0);
}

console.log(`[lab] DVGA 就绪：${BASE}（第三方 GraphQL 靶场 = GraphQL 面外部裁判；真值来自官方源码）`);

const rows = [];
let truePositives = 0;
let missed = 0;
let falsePositives = 0;
const SAFE_MIN_REQUESTS = 30;
let weakEvidence = 0;

for (const ep of ENDPOINTS) {
  const r = await scanOne(ep);
  const isVuln = ep.kind === 'vuln';
  const minReq = ep.minRequests ?? SAFE_MIN_REQUESTS;
  if (isVuln) {
    if (r.vulns > 0) truePositives += 1;
    else missed += 1;
  } else if (r.vulns > 0) {
    falsePositives += 1;
  } else if (r.requests < minReq) {
    weakEvidence += 1;
  }
  rows.push({ ...ep, ...r });
  let mark;
  if (isVuln) mark = r.vulns > 0 ? '✅' : '❌漏检';
  else if (r.vulns > 0) mark = '❌误报';
  else if (r.requests < minReq) mark = '⚠️证据不足';
  else mark = minReq === 0 ? '✅结构对照' : '✅';
  console.log(
    `${mark} [${isVuln ? '真值漏洞' : '安全端点'}] vulns=${r.vulns} 请求=${r.requests} ` +
    `${ep.method || 'GET'} ${ep.path} :: ${ep.desc}`
  );
  if (r.techniques.length) console.log(`     命中技术：${r.techniques.join(', ')}`);
  if (r.detail.length) console.log(`     命中明细：${r.detail.join(' | ')}`);
}

const vulnTotal = ENDPOINTS.filter((e) => e.kind === 'vuln').length;
console.log('\n=== 外部裁判汇总（DVGA / GraphQL）===');
console.log(`真值漏洞端点：检出 ${truePositives}/${vulnTotal}（漏检 ${missed}）`);
console.log(`安全端点误报：${falsePositives}（须为 0）`);
console.log(`安全端点证据不足（请求<各自下限；常规 ${SAFE_MIN_REQUESTS}）：${weakEvidence}（须为 0）`);
const pass = missed === 0 && falsePositives === 0 && weakEvidence === 0;
console.log(pass
  ? '✅ DVGA 外部裁判通过：GraphQL 注入可检出 且 安全端点零误报'
  : '❌ 外部裁判未通过（漏检／误报／安全端点没真测，见上表）');
process.exit(pass ? 0 : 1);

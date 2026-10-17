// ============================================================================
// e2e/juice-shop-lab/run.mjs —— [D88 2026-10-18] 第三方真框架靶场（外部裁判）
//
// ── 为什么需要这个靶场（本仓最硬的一类缺口）────────────────────────────────
// 此前 37 个 e2e 靶场除 sqli-labs（还是本项目自己写的 Python 复刻，真值自证）外
// **全部自建** ⇒ 误报率与检出率只有「自己出题自己判卷」的证据。
// 本靶场用 **OWASP Juice Shop**（第三方活跃项目：Angular + Sequelize ORM + SQLite，
// 14k+ stars）作为**外部裁判**，真值不是本项目编写的断言。
//
// ── 它已经抓到过什么（这是本靶场存在的实证价值，不是设计意图）──────────────
// 首跑即命中一条**真漏检**：`/rest/products/search?q=` 存在可打穿 10 列的 UNION 注入，
// 本引擎 0 检出，而 sqlmap 1.10.7 同题检出成功（boolean-based blind + 确认 SQLite）。
// 根因：闭合候选表缺 `%'))` 档（LIKE 上下文 × 双层括号）⇒ 闭合探测全落空 ⇒
// boundary='' ⇒ UNION 门控探针缺闭合前缀、真假响应恒等 ⇒ 该点检出不启动。
// 修复后本靶场转为「回归判据」：真漏洞必须检出、安全端点必须零误报。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要 Juice Shop 已构建并运行（见 README：codeload tarball + npm install --omit=dev
// + npm rebuild sqlite3 + 前端单独构建）。未就绪时输出 `[SKIP]` 并以 **exit 0** 退出
// —— 与 `e2e/oob-real-lab` 同口径：环境缺失不该让门禁红，但也**不计入通过**
// （acceptance 的 assert 读文本判据，不看退出码，正是为了堵「退出码恒 0 = 永远绿」）。
//
// 复跑：JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const BASE = process.env.JUICE_BASE || 'http://127.0.0.1:3199';
const TIMEOUT_MS = Number(process.env.JUICE_LAB_TIMEOUT_MS) || 200000;

/** 靶场端点清单：真漏洞端点（必须检出）与安全端点（必须零误报） */
const ENDPOINTS = [
  {
    path: '/rest/products/search?q=apple',
    kind: 'vuln',
    desc: '商品搜索（Sequelize 原生 query 字符串拼接 + LIKE + 双层括号）',
    // 真值来源（外部、非本项目编写）：OWASP Juice Shop 官方 `routes/search.ts` 中
    // models.sequelize.query(`... name LIKE '%${criteria}%' ...`) 直接拼接；官方 SOLUTIONS.md
    // 亦把该端点列为 SQL 注入挑战目标。实机可打穿证明：
    //   q=apple')) UNION SELECT 1,2,...,10-- -   →  返回伪造行（列数=10）
  },
  // ⚠ 安全端点必须**带可测参数**：无参数的路径（如 /api/Products/1）不会产生任何请求，
  // 那种「0 检出」只是「没测过」，不构成零误报证据（本靶场首版即犯此错，已纠正）。
  // 下列端点均实测会产生数十至上百请求，零检出才有证明力。
  { path: '/api/Feedbacks/?limit=2', kind: 'safe', desc: '反馈列表分页（ORM 参数化，实测 105 请求）' },
  { path: '/api/Challenges/?name=Score%20Board', kind: 'safe', desc: 'challenges 过滤（ORM where 对象）' },
  { path: '/rest/user/security-question?email=x%40y.z', kind: 'safe', desc: '密保问题查询（ORM 参数化）' },
  { path: '/api/Products/?name=apple', kind: 'safe', desc: '商品列表过滤（ORM where）' },
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

/** 靶场是否就绪（未就绪 ⇒ SKIP，不判红） */
async function reachable() {
  try {
    const r = await fetch(`${BASE}/rest/products/search?q=apple`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return false;
    const j = await r.json().catch(() => null);
    // 必须是 Juice Shop 形态（有 products 数据），避免把别的服务误当靶场
    return !!(j && j.status === 'success' && Array.isArray(j.data));
  } catch {
    return false;
  }
}

/** 扫描单个端点，返回漏洞条数 */
async function scanOne(url) {
  const sm = new ScanManager({});
  const id = await sm.start({ url, config: SCAN_CFG });
  const t0 = Date.now();
  for (;;) {
    const st = sm.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) {
      const rep = sm.getReport(id) || {};
      const counts = rep.summary?.validity?.counts || {};
      return {
        vulns: (rep.vulns || []).length,
        techniques: (rep.vulns || []).map((v) => v.technique || v.vulnType?.nameEn || '?'),
        requests: counts.total || 0,
        verdict: rep.summary?.verdict || '-',
      };
    }
    if (Date.now() - t0 > TIMEOUT_MS) {
      sm.stop(id);
      return { vulns: -1, techniques: [], requests: 0, verdict: 'timeout' };
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

if (!(await reachable())) {
  console.log(`[SKIP] Juice Shop 靶场不可达（${BASE}）—— 需先构建并启动，跳过（不计通过亦不计失败）`);
  console.log('       构建见本仓库 docs 或记忆：codeload tarball → npm install --omit=dev →');
  console.log('       npm rebuild sqlite3 → frontend/ 单独 install + 关字体内联 → npm start');
  process.exit(0);
}

console.log(`[lab] Juice Shop 就绪：${BASE}（第三方真框架 + 真 ORM + 真数据库 = 外部裁判）`);
const rows = [];
let falsePositives = 0;
let truePositives = 0;
let missed = 0;

for (const ep of ENDPOINTS) {
  const url = `${BASE}${ep.path}`;
  const r = await scanOne(url);
  const isVuln = ep.kind === 'vuln';
  if (isVuln) {
    if (r.vulns > 0) truePositives += 1;
    else missed += 1;
  } else if (r.vulns > 0) {
    falsePositives += 1;
  }
  rows.push({ ...ep, ...r });
  const mark = isVuln ? (r.vulns > 0 ? '✅' : '❌漏检') : r.vulns > 0 ? '❌误报' : '✅';
  console.log(
    `${mark} [${isVuln ? '真值漏洞' : '安全端点'}] vulns=${r.vulns} 请求=${r.requests} ${ep.path}`
  );
  if (r.techniques.length) console.log(`     命中技术：${r.techniques.join(', ')}`);
}

console.log('\n=== 外部裁判汇总 ===');
console.log(`真值漏洞端点：检出 ${truePositives}/${ENDPOINTS.filter((e) => e.kind === 'vuln').length}（漏检 ${missed}）`);
console.log(`安全端点误报：${falsePositives}（须为 0）`);
const pass = missed === 0 && falsePositives === 0;
console.log(pass
  ? '✅ Juice Shop 外部裁判通过：真漏洞可检出 且 安全端点零误报'
  : '❌ 外部裁判未通过（漏检或误报，见上表）');
process.exit(pass ? 0 : 1);

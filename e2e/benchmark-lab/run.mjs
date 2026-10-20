// ============================================================================
// e2e/benchmark-lab/run.mjs —— [D114 2026-10-20] 外部裁判 4 号：OWASP Benchmark
//
// ── 为什么需要第四个外部靶场 ────────────────────────────────────────────────
// 前三个外部裁判各补一块，但都剩同一个缺口：**注入面太窄**。
//   · Juice Shop：query + JSON body
//   · VAmPI：URL 路径段（+ D113 的 Bearer 认证）
//   · DVWA：query / POST 表单 / cookie
// **没有一个覆盖 HTTP header 位置的注入点**（D113 明确把「VAmPI 头注入形态未覆盖」
// 写进了待推进 —— Authorization 头不能当注入点，打了 token 会坏，那是另一回事）。
//
// OWASP Benchmark（`OWASP-Benchmark/BenchmarkJava`，行业通用基准，28887 个用例、
// 官方 `expectedresults-1.2.csv` 逐条标注 real vulnerability true/false）补的正是这个：
// 同族用例里官方明确标注「可注入 / 不可注入」的**大规模 A/B 集**，且注入面横跨
// query / header / cookie 三种位置。
//
// 本裁判取子集而非全集：504 个 sqli 用例（CWE-89）里筛出
//   · query 形态、字符串拼接、非 `{call`、非 preparedStatement 的 **真值 10 个**
//   · 同条件的**安全对照 8 个**（官方标注 real=false，同族实现走了参数化/校验）
//   · header 形态真值 2 个（新注入面，前三个裁判从未覆盖）
// 全集留给后续批次（`benchmark-sqli-index.json` 索引已生成，见 README）。
//
// ── 真值来源（外部，非本仓编写）─────────────────────────────────────────────
// `expectedresults-1.2.csv`：`<test name>, sqli, <real vulnerability>, 89`。
// URL 形态从各用例源码的 `@WebServlet(value = "/sqli-XX/BenchmarkTestNNNNN")` 提取；
// 参数名 = 用例类名（官方约定）。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要 Benchmark 已编译并部署（JDK21 + Maven + cargo tomcat，见同目录 README.md）。
// 未就绪时输出 `[SKIP]` 并以 **exit 0** 退出；acceptance 读文本判据（不看退出码）。
//
// 复跑：
//   BENCHMARK_BASE=http://127.0.0.1:8080/benchmark node e2e/benchmark-lab/run.mjs
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const BASE = process.env.BENCHMARK_BASE || 'https://127.0.0.1:8443/benchmark';
const TIMEOUT_MS = Number(process.env.BENCHMARK_LAB_TIMEOUT_MS) || 200000;

// cargo 的 deploy profile 起的是 **https/8443 + 自签证书**。
// 引擎侧用 config.insecureTls（axios/undici 专用 Agent，按需降级）；
// 本文件的就绪探活用全局 fetch —— Node 的 fetch 不认 per-request TLS 选项，
// 只能在进程级关掉证书校验。⚠ 仅限本进程（本地靶场探活），不影响引擎与其它测试。
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// cargo 的 deploy profile 起的是 **https/8443 + 自签证书** ⇒ 必须显式 insecureTls。
const SCAN_CFG_BASE = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 12000,
  techniques: ['union', 'boolean', 'error', 'time'],
  enableExtract: false,
  level: 2,
  risk: 2,
  productionMode: false,
  insecureTls: true,
};

/**
 * 子集清单（从 504 个 sqli 用例中按条件筛出，索引见 README「子集选择」）。
 * `kind`: 'query' ⇒ query 参数；'header' ⇒ HTTP 头（官方从 getHeader 取值）
 * `vuln`: 官方 CSV 标注的 real vulnerability
 */
const CASES = [
  // ── query 真值（官方标注 real=true）────────────────────────────────────
  { name: 'BenchmarkTest00024', path: '/sqli-00/BenchmarkTest00024', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00025', path: '/sqli-00/BenchmarkTest00025', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00026', path: '/sqli-00/BenchmarkTest00026', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00027', path: '/sqli-00/BenchmarkTest00027', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00032', path: '/sqli-00/BenchmarkTest00032', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00033', path: '/sqli-00/BenchmarkTest00033', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00034', path: '/sqli-00/BenchmarkTest00034', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00037', path: '/sqli-00/BenchmarkTest00037', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00038', path: '/sqli-00/BenchmarkTest00038', kind: 'query', vuln: true },
  { name: 'BenchmarkTest00039', path: '/sqli-00/BenchmarkTest00039', kind: 'query', vuln: true },
  // ── query 安全对照（官方标注 real=false，同族实现）──────────────────────
  { name: 'BenchmarkTest00430', path: '/sqli-00/BenchmarkTest00430', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00432', path: '/sqli-00/BenchmarkTest00432', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00436', path: '/sqli-00/BenchmarkTest00436', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00437', path: '/sqli-00/BenchmarkTest00437', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00440', path: '/sqli-00/BenchmarkTest00440', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00511', path: '/sqli-00/BenchmarkTest00511', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00513', path: '/sqli-00/BenchmarkTest00513', kind: 'query', vuln: false },
  { name: 'BenchmarkTest00514', path: '/sqli-00/BenchmarkTest00514', kind: 'query', vuln: false },
  // ── header 真值（官方从 request.getHeader 取值；前三个裁判未覆盖的注入面）──
  { name: 'BenchmarkTest00018', path: '/sqli-00/BenchmarkTest00018', kind: 'header', vuln: true },
  { name: 'BenchmarkTest00194', path: '/sqli-00/BenchmarkTest00194', kind: 'header', vuln: true },
];

// 安全端点「算证据」的最低请求数：低于此值说明点被剪枝/预筛跳过，零检出只是没测过。
const SAFE_MIN_REQUESTS = 30;

const SCAN_CFG = SCAN_CFG_BASE;

/** 就绪探活：任取一个 query 用例无参请求，必须是 Benchmark 形态（200 且无异常页） */
async function reachable() {
  try {
    const r = await fetch(`${BASE}${CASES[0].path}`, { signal: AbortSignal.timeout(8000) });
    if (r.status !== 200) return false;
    const t = await r.text();
    // Benchmark 无参时返回空或固定文案；404 说明 context path 不对（未部署）
    return !/404|Not Found/i.test(t);
  } catch {
    return false;
  }
}

async function scanOne(c) {
  const sm = new ScanManager({});
  const target = {
    url: `${BASE}${c.path}`,
    // [D114] header 用例必须显式 testHeaders：TargetParser 只在 level>=3 或 testHeaders
    // 时把 headerParams 变成注入点；本 lab 全局 level=2（query 用例的默认档），漏了这一步
    // 会出现「header 用例 0 请求 + 没有匹配到任何注入点」的假漏检（首跑实测）。
    config: { ...SCAN_CFG, testParameter: [c.name], ...(c.kind === 'header' ? { testHeaders: true } : {}) },
  };
  if (c.kind === 'header') {
    // 注入面在 HTTP 头（官方 getHeader(类名)）；显式 headerParams 传入基线值。
    target.headerParams = { [c.name]: 'baseline' };
  } else {
    target.url = `${BASE}${c.path}?${c.name}=baseline`;
  }
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
      return { vulns: -1, techniques: [], requests: 0, verdict: 'timeout' };
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

if (!(await reachable())) {
  console.log(`[SKIP] OWASP Benchmark 靶场不可达（${BASE}）—— 需先编译并部署，跳过（不计通过亦不计失败）`);
  console.log('       构建与启动见 e2e/benchmark-lab/README.md（JDK21 + Maven + cargo tomcat；');
  console.log('       mvn initialize clean package cargo:run -Pdeploy；HSQLDB 文件库自动建）');
  process.exit(0);
}

console.log(`[lab] OWASP Benchmark 就绪：${BASE}（第三方行业基准 + 官方逐条标注真值 = 外部裁判 4 号）`);
console.log('[lab] 子集：query 真值 10 + query 安全对照 8 + header 真值 2（新注入面）');

const rows = [];
let truePositives = 0;
let missed = 0;
let falsePositives = 0;
let weakEvidence = 0;
const missedList = [];
const fpList = [];

for (const c of CASES) {
  const r = await scanOne(c);
  if (c.vuln) {
    if (r.vulns > 0) truePositives += 1;
    else {
      missed += 1;
      missedList.push(c.name);
    }
  } else if (r.vulns > 0) {
    falsePositives += 1;
    fpList.push(c.name);
  } else if (r.requests < SAFE_MIN_REQUESTS) {
    weakEvidence += 1;
  }
  rows.push({ ...c, ...r });
  const mark = c.vuln
    ? r.vulns > 0 ? '✅' : '❌漏检'
    : r.vulns > 0 ? '❌误报' : r.requests < SAFE_MIN_REQUESTS ? '⚠️证据不足' : '✅';
  const tag = c.vuln ? '真值漏洞' : '安全对照';
  const where = c.kind === 'header' ? `header ${c.name}` : `query ${c.name}`;
  console.log(`${mark} [${tag}/${c.kind}] vulns=${r.vulns} 请求=${r.requests} ${where}`);
  if (r.techniques.length) console.log(`     命中技术：${r.techniques.join(', ')}`);
  if (r.detail.length) console.log(`     命中明细：${r.detail.join(' | ')}`);
}

const vulnTotal = CASES.filter((c) => c.vuln).length;
const safeTotal = CASES.filter((c) => !c.vuln).length;
const headerTotal = CASES.filter((c) => c.kind === 'header').length;
console.log('\n=== 外部裁判汇总（OWASP Benchmark 子集）===');
console.log(`真值漏洞用例：检出 ${truePositives}/${vulnTotal}（漏检 ${missed}${missedList.length ? '：' + missedList.join(',') : ''}）`);
console.log(`安全对照误报：${falsePositives}/${safeTotal}（须为 0${fpList.length ? '：' + fpList.join(',') : ''}）`);
console.log(`安全对照证据不足（请求<${SAFE_MIN_REQUESTS}）：${weakEvidence}（须为 0）`);
console.log(`header 注入面用例：${headerTotal}（前三个外部裁判未覆盖的形态）`);
const pass = missed === 0 && falsePositives === 0 && weakEvidence === 0;
console.log(pass
  ? '✅ Benchmark 外部裁判通过：官方标注真值全部检出 且 官方标注安全用例零误报'
  : '❌ 外部裁判未通过（漏检／误报／安全端点没真测，见上表）');
process.exit(pass ? 0 : 1);

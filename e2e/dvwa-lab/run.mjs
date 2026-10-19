// ============================================================================
// e2e/dvwa-lab/run.mjs —— [D112 2026-10-20] 外部裁判 3 号：DVWA（PHP + MySQL）
//
// ── 为什么再加第三个外部靶场 ────────────────────────────────────────────────
// 前两个外部裁判各有盲区：
//   · Juice Shop（D88/D109）：Node + Sequelize + SQLite，注入点在 query / JSON body
//   · VAmPI（D110）：Python + SQLAlchemy + SQLite，注入点在 URL 路径段
// 两个都是 **SQLite**、都是 **非 PHP 栈**。任何「检出率」结论若只靠它们，等于只证明
// 「本引擎在 SQLite 上能打」——MySQL/MariaDB 的语法差异（注释符 `#`、`LIMIT`、
// `information_schema` 结构、`mysqli_error` 回显形态）完全没被外部证据覆盖。
//
// DVWA（digininja/DVWA，第三方故意脆弱应用，行业通用基准）补三件前两者都没有的事：
//   1. **PHP + MySQL/MariaDB 栈**（`mysqli_query` 直拼 + `mysqli_error` 回显）
//   2. **cookie 位置注入点**（`$_COOKIE['id']` 直接进 WHERE）——前两个裁判都没有
//   3. **四档官方难度开关**：low 直拼 / medium 转义但数值型无引号 / high cookie /
//      impossible PDO 参数化 ⇒ **同路径 A/B 由官方源码保证**，不是本仓造的对照
//
// ── 真值（外部源码，非本仓编写）─────────────────────────────────────────────
// `vulnerabilities/sqli/source/low.php`：
//   $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"
// `vulnerabilities/sqli_blind/source/high.php`：
//   $id = $_COOKIE['id']; $query = "... WHERE user_id = '$id' LIMIT 1;"
// `vulnerabilities/sqli/source/impossible.php`：
//   is_numeric($id) + PDO prepare(bindParam PARAM_INT) ⇒ 官方「不可利用」档
//
// 实机复核（curl 手测，写进 results 报告）：
//   sqli low  id=1                      → First name: admin / Surname: admin
//   sqli low  id=1'                     → 'You have an error in your SQL syntax ... near ''1''''
//   sqli low  id=1' AND 1=1-- -         → 有 admin 回显；1=2 → 无回显   ⇒ 布尔可分
//   sqli low  id=1' UNION SELECT 1,2-- -→ 回显 1 / 2                     ⇒ UNION 2 列
//   blind low id=1' AND 1=1-- -         → "User ID exists"；1=2 → "MISSING"
//   blind high cookie id=1'/**/AND/**/1=1# → exists；1=2 → MISSING      ⇒ cookie 点可分
//   sqli impossible id=1'               → 无回显、无 SQL 错误（is_numeric 拦死）
// ⚠ cookie 值 PHP **不做** urldecode ⇒ `%27` 会被当字面量，真值探针必须发原始字符。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要 DVWA + PHP + MySQL 在跑（构建与启动见同目录 README.md）。未就绪时输出 `[SKIP]`
// 并以 **exit 0** 退出 —— 与前两个外部裁判同口径：环境缺失不该让门禁红，但**不计入通过**
// （acceptance 读文本判据，不看退出码，堵「退出码恒 0 = 永远绿」）。
//
// 复跑：DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const BASE = process.env.DVWA_BASE || 'http://127.0.0.1:8099';
const TIMEOUT_MS = Number(process.env.DVWA_LAB_TIMEOUT_MS) || 260000;
const SESSION = process.env.DVWA_PHPSESSID || 'dvwa-lab-session';

/**
 * 端点清单。
 * `level`  → DVWA 官方难度（经 security cookie 切换，官方源码分档，非本仓改写）
 * `kind`   → 'vuln' 必须检出；'safe'（impossible 档）必须零检出
 * `cookie` → 额外 cookie 注入点载体（blind high 的注入点就是 cookie `id`）
 */
const ENDPOINTS = [
  {
    path: '/vulnerabilities/sqli/?id=1&Submit=Submit',
    level: 'low',
    kind: 'vuln',
    test: ['id'],
    desc: 'GET id 直拼（官方 low.php：WHERE user_id = \'$id\' 单引号包裹，mysqli_error 回显）',
  },
  {
    // 同源复检：与第 1 条同一个注入点，只把取值换成良性 2。
    // 钉住「检出不靠输入自带畸形」——换良性值就不报说明判据只是模式匹配。
    // 统计单列，不并入真值分母（防分母灌水，与 VAmPI / Juice Shop 同口径）。
    path: '/vulnerabilities/sqli/?id=2&Submit=Submit',
    level: 'low',
    kind: 'vuln',
    test: ['id'],
    homologous: true,
    desc: '同注入点换良性取值 id=2（同源复检）',
  },
  {
    path: '/vulnerabilities/sqli_blind/?id=1&Submit=Submit',
    level: 'low',
    kind: 'vuln',
    test: ['id'],
    desc: '盲注（官方去掉 or die ⇒ 无错误回显，只剩 exists/MISSING 布尔）',
  },
  {
    // ★ 本靶场最有价值的一点：注入点在 **cookie** 里，且官方还塞了随机 sleep(2~4)
    // 噪声（MISSING 分支 rand(0,5)==3）⇒ 顺带压一下时间通道的抗噪能力。
    path: '/vulnerabilities/sqli_blind/',
    level: 'high',
    kind: 'vuln',
    cookie: { id: '1' },
    test: ['id'],
    desc: 'Cookie 位置注入（官方 high.php：`$_COOKIE[\'id\']` 直拼 + MISSING 随机 sleep 噪声）',
  },
  {
    // medium：mysqli_real_escape_string 转义，但 SQL 是 **数值型无引号**
    // （`WHERE user_id = $id`）⇒ 转义无效、仍可注入。且是 POST 表单。
    path: '/vulnerabilities/sqli/',
    level: 'medium',
    kind: 'vuln',
    method: 'POST',
    body: { id: '1', Submit: 'Submit' },
    test: ['id'],
    desc: 'POST 表单 + 转义绕过（官方 medium.php：数值型无引号 ⇒ real_escape_string 拦不住）',
  },
  {
    // [D113] 盲注 + POST 表单 + 转义绕过：官方 sqli_blind/medium.php 去掉 `or die`
    // ⇒ 无错误回显，只剩 exists/MISSING 布尔（比 sqli/medium 更难一档：三通道只剩两通道）。
    // 真值 curl 复核：id=1 AND 1=1# → exists；id=1 AND 1=2# → MISSING。
    path: '/vulnerabilities/sqli_blind/',
    level: 'medium',
    kind: 'vuln',
    method: 'POST',
    body: { id: '1', Submit: 'Submit' },
    test: ['id'],
    desc: '盲注 + POST 表单（官方 medium.php：无 or die ⇒ 仅布尔可分）',
  },
  {
    path: '/vulnerabilities/sqli/?id=1&Submit=Submit',
    level: 'impossible',
    kind: 'safe',
    test: ['id'],
    // ⚠ impossible 档 is_numeric 直接拦死 ⇒ 会命中「输入校验型可证安全跳过」剪枝，
    // 只发几个请求就收工。**几个请求的 0 检出不是零误报证据**（VAmPI 已栽过一次），
    // 故显式关掉剪枝，打满预算后再说「零误报」。
    cfg: { validationSkip: false },
    desc: '同路径 impossible 档（官方 PDO prepare + is_numeric ⇒ A/B 核心对照）',
  },
  {
    path: '/vulnerabilities/sqli_blind/?id=1&Submit=Submit',
    level: 'impossible',
    kind: 'safe',
    test: ['id'],
    cfg: { validationSkip: false },
    desc: '盲注同路径 impossible 档（PDO + is_numeric + CSRF token）',
  },
];

// 安全端点「算证据」的最低请求数：低于此值说明点被剪枝/预筛跳过，零检出只是没测过。
const SAFE_MIN_REQUESTS = 30;

const SCAN_CFG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 15000,
  techniques: ['union', 'boolean', 'error', 'time'],
  enableExtract: false,
  level: 2,
  risk: 2,
  productionMode: false,
};

/** 靶场是否就绪（必须是 DVWA 形态，避免把别的服务误当靶场） */
async function reachable() {
  try {
    const r = await fetch(`${BASE}/login.php`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return false;
    const t = await r.text();
    return t.includes('Damn Vulnerable Web Application') || t.includes('DVWA');
  } catch {
    return false;
  }
}

async function scanOne(ep) {
  const sm = new ScanManager({});
  const target = {
    url: `${BASE}${ep.path}`,
    // 官方文档分档靠 `security` cookie；PHPSESSID 只为维持会话（disable_authentication 下
    // 不校验登录态）。两者都会被 level≥2 当注入点候选 ⇒ 用 testParameter 精确收敛到目标参数，
    // 顺带压测 D41 的 `-p` 定向能力在真实多 cookie 场景下的表现。
    cookieParams: { security: ep.level, PHPSESSID: SESSION, ...(ep.cookie || {}) },
    config: { ...SCAN_CFG, ...(ep.cfg || {}), testParameter: ep.test || [] },
  };
  if (ep.method) target.method = ep.method;
  if (ep.body) target.bodyParams = { ...ep.body };
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
  console.log(`[SKIP] DVWA 靶场不可达（${BASE}）—— 需先启动 PHP + MySQL + DVWA，跳过（不计通过亦不计失败）`);
  console.log('       构建与启动见 e2e/dvwa-lab/README.md（codeload tarball → config.inc.php →');
  console.log('       setup.php 建库 → php -S 127.0.0.1:8099）；安全对照缺一即不算通过');
  process.exit(0);
}

console.log(`[lab] DVWA 就绪：${BASE}（第三方真框架 + PHP 8.3 + MariaDB 10.11 = 外部裁判 3 号）`);
console.log('[lab] 真值来自官方源码四档分档（low/medium/high/impossible），非本仓断言');

const rows = [];
let truePositives = 0;
let missed = 0;
let homoHit = 0;
let homoTotal = 0;
let falsePositives = 0;
let weakEvidence = 0;

for (const ep of ENDPOINTS) {
  const r = await scanOne(ep);
  const isVuln = ep.kind === 'vuln';
  if (isVuln) {
    if (ep.homologous) {
      homoTotal += 1;
      if (r.vulns > 0) homoHit += 1;
    } else if (r.vulns > 0) {
      truePositives += 1;
    } else {
      missed += 1;
    }
  } else if (r.vulns > 0) {
    falsePositives += 1;
  } else if (r.requests < SAFE_MIN_REQUESTS) {
    weakEvidence += 1;
  }
  rows.push({ ...ep, ...r });
  let mark;
  if (isVuln) mark = r.vulns > 0 ? '✅' : '❌漏检';
  else if (r.vulns > 0) mark = '❌误报';
  else if (r.requests < SAFE_MIN_REQUESTS) mark = '⚠️证据不足';
  else mark = '✅';
  const tag = isVuln ? (ep.homologous ? '同源复检' : '真值漏洞') : '安全端点';
  const where = ep.cookie ? `cookie ${JSON.stringify(ep.cookie)} @` : '';
  console.log(
    `${mark} [${tag}/${ep.level}] vulns=${r.vulns} 请求=${r.requests} ` +
    `${ep.method || 'GET'} ${where}${ep.path}`
  );
  if (r.techniques.length) console.log(`     命中技术：${r.techniques.join(', ')}`);
  if (r.detail.length) console.log(`     命中明细：${r.detail.join(' | ')}`);
}

const vulnTotal = ENDPOINTS.filter((e) => e.kind === 'vuln' && !e.homologous).length;
console.log('\n=== 外部裁判汇总（DVWA）===');
console.log(`真值漏洞端点：检出 ${truePositives}/${vulnTotal}（漏检 ${missed}）`);
console.log(`同源复检（同点换良性值）：检出 ${homoHit}/${homoTotal}`);
console.log(`安全端点误报：${falsePositives}（须为 0）`);
console.log(`安全端点证据不足（请求<${SAFE_MIN_REQUESTS}）：${weakEvidence}（须为 0）`);
const pass = missed === 0 && falsePositives === 0 && weakEvidence === 0;
console.log(pass
  ? '✅ DVWA 外部裁判通过：PHP+MySQL 栈真漏洞可检出 且 同路径 impossible 档零误报'
  : '❌ 外部裁判未通过（漏检／误报／安全端点没真测，见上表）');
process.exit(pass ? 0 : 1);

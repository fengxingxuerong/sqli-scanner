// ============================================================================
// e2e/vampi-lab/run.mjs —— [D110 2026-10-19] 外部裁判 2 号：VAmPI（Flask + SQLAlchemy + SQLite）
//
// ── 为什么再加一个外部靶场 ─────────────────────────────────────────────────
// Juice Shop（D88/D109）解决了「自己出题自己判卷」，但外部裁判只有 **1 个项目、
// 2 个真值端点**，任何「外部检出率」类结论都撑不起来（单项目 = 单数据点）。
// VAmPI（erev0s/VAmPI，第三方故意脆弱 API，用来评估第三方工具对 API 的发现能力）
// 带来 Juice Shop 没有的形态：**URL 路径段（REST 风格 `/users/v1/{username}`）注入点**，
// 且真值只来自官方源码 `models/user_model.py:72` 的 f-string 拼接，非本仓断言。
//
// ── 本靶场最硬的一点：A/B 同端点对照 ───────────────────────────────────────
// VAmPI 官方自带 `vulnerable` 开关（app.py 读 env，默认 1）：
//   vuln=1 → `SELECT * FROM users WHERE username = '<输入>'` 拼接
//   vuln=0 → `User.query.filter_by(username=…)` 参数化
// 于是可以起**两个实例、同一路径、同一参数形态**，唯一变量是官方开关：
//   · 5000（vuln=1）`/users/v1/{username}` 必须检出
//   · 5001（vuln=0）`/users/v1/{username}` 必须零检出
// 这比「另找几个无关的安全端点」强：零误报证据钉在**同一个注入点形态**上，
// 排除「安全端点其实是没测到」的老毛病（本仓在 Juice Shop 首版就栽过：
// 无参数路径 0 检出只是没测过）。
//
// ── 真值（外部源码，非本仓编写）─────────────────────────────────────────────
// `models/user_model.py`：
//   if vuln:  # SQLi Injection
//     user_query = f"SELECT * FROM users WHERE username = '{username}'"
//     query = db.session.execute(text(user_query))
// 实机三通道表现（手工复核，写进 results 报告）：
//   zzz' OR 1=1-- -   → 200 {"username":"name1",...}   （fetchone 取首行）
//   zzz' OR 1=2-- -   → 404 User not found              ⇒ 布尔可分
//   zzz' UNION SELECT 1,2,3,4,5-- - → 200 {"username":"2","email":"4"} ⇒ 5 列回显
//   zzz' AND SLEEP(1)-- - → 500（SQLite 无 sleep，错误页泄漏 SQL）⇒ 报错通道有信号
//
// ── [D113 2026-10-20] 认证场景扩面（Bearer + BOLA 端点）──────────────────────
// D110 只覆盖了「匿名 + 无认证头」的形态。真实渗透中扫描器几乎总是带着会话打的，
// 而本仓最贵的一类教训恰恰出在认证链路上 —— D91：`--header "cookie:"` 双处存储 +
// axios 同名大小写头后写赢，124 个探针全打在**未注入的值**上，静默假阴性。
// 本轮把 VAmPI 的认证面纳入裁判：
//   · 官方 `api_views/books.py:get_by_title` 以 `filter_by(book_title=…)` 参数化查询，
//     且以 `token_validator(request.headers.get('Authorization'))` 门禁 ⇒ **带 Bearer
//     的安全端点**：认证头存在 + 参数化 + 响应可分（200 有书 / 404 无书）。
//   · 同一实例上 `/users/v1/{username}`（拼接真值）**带同一个 Bearer 头** ⇒ 认证头
//     不得破坏注入检出（D91 同型夹击的回归面）。
// 实现要点：
//   · token 默认 60 秒过期（`app.py: alive = getenv('tokentimetolive', 60)`）⇒ 一轮扫描
//     会跨过期 ⇒ 起靶场时必须设 `tokentimetolive=7200`（官方 env，README 已载）。
//   · 每个端点显式 `testParameter` 收敛到唯一注入点（path 段），避免把 Authorization
//     头本身当注入点打（那会把 token 打坏，测的是头注入而非 SQLi）。
//
// ── 依赖与门控（按需 SKIP，不伪装通过）──────────────────────────────────────
// 需要两个 VAmPI 实例在跑（构建与启动见同目录 README.md）。未就绪时输出 `[SKIP]`
// 并以 **exit 0** 退出 —— 与 juice-shop-lab 同口径：环境缺失不该让门禁红，
// 但**不计入通过**（acceptance 读文本判据，不看退出码，堵「退出码恒 0 = 永远绿」）。
//
// 复跑：
//   VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 \
//     node e2e/vampi-lab/run.mjs
// ============================================================================

import { ScanManager } from '../../server/src/engine/ScanManager.js';

const BASE_VULN = process.env.VAMPI_VULN_BASE || 'http://127.0.0.1:5000';
const BASE_SAFE = process.env.VAMPI_SAFE_BASE || 'http://127.0.0.1:5001';
const TIMEOUT_MS = Number(process.env.VAMPI_LAB_TIMEOUT_MS) || 200000;

/** [D113] 本轮注册/登录用的账号（随机后缀防跨轮撞名） */
const USER = `d113-${Math.random().toString(36).slice(2, 8)}`;
const PASS = 'Password1!';
/** [D113] 自己加一本书，保证 /books/v1/{title} 有「存在」的样本 */
const BOOK = `d113book-${Math.random().toString(36).slice(2, 8)}`;

/**
 * 端点清单。
 * `base`: 'vuln' → 官方 vulnerable=1 实例（真值拼接）；'safe' → vulnerable=0 实例（参数化）
 * `kind`: 'vuln' 必须检出；'safe' 必须零检出
 * `auth: true` ⇒ 带 Bearer 头（D113 认证场景）
 */
const ENDPOINTS = [
  {
    base: 'vuln',
    path: '/users/v1/zzz',
    kind: 'vuln',
    test: ['zzz'],
    desc: '路径段 username（官方 user_model.py:72 f-string 拼接；布尔/UNION/报错三通道均有信号）',
  },
  {
    base: 'safe',
    path: '/users/v1/zzz',
    kind: 'safe',
    test: ['zzz'],
    desc: '同路径同形态，官方 vulnerable=0 ⇒ filter_by 参数化（A/B 对照的核心）',
  },
  {
    // ⚠ 默认配置下这一点会被「输入校验型可证安全跳过」剪枝（基线 200 → 单引号 404 →
    // 良性非法值同构 ⇒ 判为白名单拦死），整点只发 5 个请求。**5 个请求的 0 检出不是
    // 零误报证据**（本仓在 Juice Shop 首版就栽过：没测过 ≠ 通过）。
    // 所以这里显式 validationSkip:false 关掉剪枝，让它打满预算后再说「零误报」。
    base: 'safe',
    path: '/users/v1/name1',
    kind: 'safe',
    test: ['name1'],
    cfg: { validationSkip: false },
    desc: '参数化实例 + 良性输入（关掉输入校验剪枝，打满请求后才是有效零误报证据）',
  },
  {
    // 同源复检，不是独立真值：与第 1 条是**同一个注入点**，只是把取值从 zzz 换成良性
    // name1。它的作用是钉住「检出不是靠输入里自带引号」——若换良性值就不报，说明判据
    // 只是畸形输入的模式匹配而非真注入证据。统计时单列，不并入真值分母（防分母灌水）。
    base: 'vuln',
    path: '/users/v1/name1',
    kind: 'vuln',
    test: ['name1'],
    homologous: true,
    desc: '同注入点换良性取值（同源复检：检出不依赖畸形输入）',
  },
  // ── [D113] 认证场景（Bearer）───────────────────────────────────────────────
  // 官方 api_views/books.py:get_by_title —— token_validator 门禁 + filter_by 参数化。
  // 它是**带认证头的安全端点**：认证头在、参数化、响应可分（200 有书 / 404 无书）。
  {
    base: 'safe',
    path: `/books/v1/${BOOK}`,
    kind: 'safe',
    auth: true,
    test: [BOOK],
    desc: '参数化实例 + Bearer 认证 + 已存在的书（官方 filter_by；200 vs 404 可分）',
  },
  {
    base: 'safe',
    path: '/books/v1/nosuchbook-d113',
    kind: 'safe',
    auth: true,
    test: ['nosuchbook-d113'],
    cfg: { validationSkip: false },
    desc: '参数化实例 + Bearer + 不存在的书（404 分支；另一条可分的输入）',
  },
  {
    // vuln=1 实例上 books 同样是 filter_by 参数化（该实例的 vuln 语义只影响 users 拼接
    // 与 BOLA 越权）⇒ 也是安全端点：证明「同一实例上真值点检得出、参数化点不误报」。
    // ⚠ 必须显式关掉输入校验剪枝：该点基线 200 → 单引号 404 ⇒ 剪枝判「白名单拦死」只发
    // 5 请求（D111 同款陷阱：5 请求的 0 检出不是零误报证据）。
    base: 'vuln',
    path: `/books/v1/${BOOK}`,
    kind: 'safe',
    auth: true,
    test: [BOOK],
    cfg: { validationSkip: false },
    desc: '漏洞实例上的 books 端点（vuln 语义只作用于 users/BOLA，books 仍参数化）',
  },
  {
    // ★ D91 回归面：同一个 Bearer 头 + 拼接真值点 ⇒ 认证头不得破坏注入检出。
    base: 'vuln',
    path: '/users/v1/zzz',
    kind: 'vuln',
    auth: true,
    test: ['zzz'],
    desc: '带 Bearer 的真值路径段（认证场景下仍须检出 —— D91 夹击假阴性的回归面）',
  },
  {
    base: 'vuln',
    path: '/users/v1/name1',
    kind: 'vuln',
    auth: true,
    test: ['name1'],
    homologous: true,
    desc: '带 Bearer 的同源复检（换良性取值仍须检出）',
  },
];

// 安全端点「算证据」的最低请求数：低于此值说明点被剪枝/预筛跳过，零检出只是没测过。
const SAFE_MIN_REQUESTS = 30;

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
  // 真值点在 URL 路径段（REST 形态）⇒ 必须显式开启，默认关闭（零回归设计）
  testPath: true,
};

async function reachable(base) {
  try {
    const r = await fetch(`${base}/users/v1/name1`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return false;
    const t = await r.text();
    // 必须是 VAmPI 形态（有 username/email），避免把别的服务误当靶场
    return t.includes('"username"') && t.includes('"email"');
  } catch {
    return false;
  }
}

/**
 * [D113] 注册 + 登录拿 Bearer token（官方 `/users/v1/register` + `/users/v1/login`，
 * 登录响应字段是 `auth_token`）。返回 null 表示认证链路不可用。
 */
async function registerAndLogin(base) {
  const user = `${USER}-${base === BASE_SAFE ? 'safe' : 'vuln'}`;
  try {
    const reg = await fetch(`${base}/users/v1/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: PASS, email: `${user}@example.com` }),
      signal: AbortSignal.timeout(10000),
    });
    if (!reg.ok) return { user, token: null };
    const login = await fetch(`${base}/users/v1/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: PASS }),
      signal: AbortSignal.timeout(10000),
    });
    const j = await login.json().catch(() => ({}));
    return { user, token: j.auth_token || null };
  } catch {
    return { user, token: null };
  }
}

/** [D113] 给自己加一本书，保证 /books/v1/{title} 的「存在」样本（200 分支）有数据 */
async function addBook(base, token, title) {
  try {
    const r = await fetch(`${base}/books/v1`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ book_title: title, secret: 'd113-secret' }),
      signal: AbortSignal.timeout(10000),
    });
    return r.ok;
  } catch {
    return false;
  }
}

async function scanOne(ep, token) {
  const base = ep.base === 'safe' ? BASE_SAFE : BASE_VULN;
  const sm = new ScanManager({});
  const target = {
    url: `${base}${ep.path}`,
    config: { ...SCAN_CFG, ...(ep.cfg || {}), ...(ep.test ? { testParameter: ep.test } : {}) },
  };
  // [D113] 认证场景：Bearer 走 headerParams（与 cookieParams 同级的显式头通道）
  if (ep.auth && token) target.headerParams = { Authorization: `Bearer ${token}` };
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
        // 命中明细（param/location/dbms）：与 sqlmap 的「Parameter/Type/DBMS」逐项对齐，
        // 便于同题对照时逐字段比对，而不是只比「检出/未检出」一个布尔。
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

const upVuln = await reachable(BASE_VULN);
const upSafe = await reachable(BASE_SAFE);
if (!upVuln || !upSafe) {
  console.log(
    `[SKIP] VAmPI 靶场不可达（vuln=${BASE_VULN} ${upVuln ? 'up' : 'down'} / ` +
    `safe=${BASE_SAFE} ${upSafe ? 'up' : 'down'}）—— 需先启动两个实例，跳过（不计通过亦不计失败）`
  );
  console.log('       构建与启动见 e2e/vampi-lab/README.md（codeload tarball → venv 装依赖 →');
  console.log('       vulnerable=1 @5000 与 vulnerable=0 @5001 双实例：安全对照缺一即不算通过）');
  process.exit(0);
}

console.log(`[lab] VAmPI 就绪：漏洞实例 ${BASE_VULN}（vulnerable=1）／对照实例 ${BASE_SAFE}（vulnerable=0）`);
console.log('[lab] 第三方真框架 + 真 ORM + 真 SQLite = 外部裁判 2 号；真值来自官方源码而非本仓断言');

// [D113] 认证链路：两实例各注册一个账号拿 token（两个实例共用同一份 SQLite，但各自
// 注册保证「登录一定成功」这条路径被真实走到）。失败不静默 —— 打印原因并把 auth 端点
// 记为「未测」（不计通过，也不伪装成零误报）。
const tokens = {};
for (const [name, base] of [['vuln', BASE_VULN], ['safe', BASE_SAFE]]) {
  const { user, token } = await registerAndLogin(base);
  tokens[name] = token;
  console.log(
    token
      ? `[lab] 认证就绪（${name}）：${user} 登录成功，Bearer token ${token.length} 字符`
      : `[lab] ⚠ 认证不可用（${name}）：${user} 注册/登录失败 ⇒ Bearer 端点将记为「未测」`
  );
}
const bookAdded = await addBook(BASE_VULN, tokens.vuln, BOOK);
console.log(
  bookAdded
    ? `[lab] 已添加样本书 ${BOOK}（/books/v1/{title} 的「存在」分支）`
    : `[lab] ⚠ 加书失败 ⇒ /books/v1/{title} 的「存在」分支无数据（该端点判据降级为不可用）`
);

const rows = [];
let truePositives = 0;
let missed = 0;
let homoHit = 0;
let homoTotal = 0;
let falsePositives = 0;
let weakEvidence = 0; // 安全端点没真测（请求数不足）⇒ 零检出不算证据
let untested = 0; // [D113] 认证链路不可用 ⇒ 端点没测（不算通过也不算失败）

for (const ep of ENDPOINTS) {
  const token = ep.auth ? tokens[ep.base === 'safe' ? 'safe' : 'vuln'] : null;
  if (ep.auth && !token) {
    untested += 1;
    console.log(`⚠️ [未测] Bearer 端点（认证链路不可用）：GET ${ep.path}`);
    rows.push({ ...ep, skipped: true });
    continue;
  }
  const r = await scanOne(ep, token);
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
  const host = ep.base === 'safe' ? BASE_SAFE : BASE_VULN;
  let mark;
  if (isVuln) mark = r.vulns > 0 ? '✅' : '❌漏检';
  else if (r.vulns > 0) mark = '❌误报';
  else if (r.requests < SAFE_MIN_REQUESTS) mark = '⚠️证据不足';
  else mark = '✅';
  const tag = isVuln ? (ep.homologous ? '同源复检' : '真值漏洞') : '安全端点';
  console.log(
    `${mark} [${tag}${ep.auth ? '+Bearer' : ''}] vulns=${r.vulns} 请求=${r.requests} GET ${host}${ep.path}`
  );
  if (r.techniques.length) console.log(`     命中技术：${r.techniques.join(', ')}`);
  if (r.detail.length) console.log(`     命中明细：${r.detail.join(' | ')}`);
}

const vulnTotal = ENDPOINTS.filter((e) => e.kind === 'vuln' && !e.homologous).length;
const safeTotal = ENDPOINTS.filter((e) => e.kind === 'safe').length;
const authEndpoints = ENDPOINTS.filter((e) => e.auth).length;
console.log('\n=== 外部裁判汇总（VAmPI）===');
console.log(`真值漏洞端点：检出 ${truePositives}/${vulnTotal}（漏检 ${missed}）`);
console.log(`同源复检（同点换良性值）：检出 ${homoHit}/${homoTotal}`);
console.log(`安全端点误报：${falsePositives}/${safeTotal}（须为 0）`);
console.log(`安全端点证据不足（请求<${SAFE_MIN_REQUESTS}）：${weakEvidence}（须为 0）`);
console.log(`Bearer 认证端点：${authEndpoints} 个（未测 ${untested}，未测须为 0）`);
const pass = missed === 0 && falsePositives === 0 && weakEvidence === 0 && untested === 0;
console.log(pass
  ? '✅ VAmPI 外部裁判通过：真漏洞可检出、同形态参数化实例零误报、Bearer 认证端点零误报'
  : '❌ 外部裁判未通过（漏检／误报／安全端点没真测／认证链路不可用，见上表）');
process.exit(pass ? 0 : 1);

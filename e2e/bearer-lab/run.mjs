// ============================================================================
// e2e/bearer-lab/run.mjs —— Bearer/Token 自动续期的真机验收（批次 D36，实战 P0-2）
//
// D36 交的是「续期编排 + 失败显形」，证据是单元 + 接线级。本套件把它换成实弹：
// 真 HTTP 靶站 + 真 JWT(HS256) 验签 + 真刷新端点 + 真 SQL 引擎（sql.js）+ 真 CLI 进程。
//
// 六个场景，各自钉一句话：
//   A 对照组（**先跑**）：只带抓包里的 Bearer、不配续期 ⇒ 令牌在扫描中途过期。
//     断言的是"不做这半程会怎样"的**当下真实形态**（靶站侧计数裁判，不是引擎自报）。
//   B 配 --refresh-url（body 带 refreshToken）⇒ 过期后自动换新令牌，注入照样抵达 SQL，
//     照样检出；靶站侧 refreshHits ≥ 1 且"过期后被拒的注入"为 0。
//   C1 续期端点自己 5xx ⇒ 结论必须降级，且 reason 里要点名"续期尝试 N 次失败 M 次 + 最后一次原因"。
//   C2 续期端点 200 但响应里没有可用 token（字段名配歪）⇒ 同下降级，why 要给出响应顶层键。
//   D 刷新凭据只在 Cookie 里（不配 --refresh-token）⇒ 走会话 jar 那条路也要真的续上。
//   SAFE 安全对照点（参数化查询）配续期 ⇒ 0 检出（证明 B 的检出不是靶站白送）。
//
// ⚠ 计时用**虚拟时钟**（每处理一条 API 请求拨快 20 秒）：真实 TTL 会让"过期发生在第几条请求"
//   变成 CI 上的抛硬币，两种情况测的根本不是同一件事。见 jwt-scheme.mjs 头部说明。
// ============================================================================
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { signToken, verifyToken, REFRESH_SECRET, REFRESHED_TTL_MS, TOKEN_TTL_MS } from './jwt-scheme.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');

const SEED = `CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price TEXT);
INSERT INTO items VALUES (1,'widget','$9.90'),(2,'gadget','$19.00'),(3,'doohickey','$5.00');`;

/** 每处理一条 API 请求，靶站的虚拟时钟拨快这么多：TTL 60s ⇒ 一枚令牌约活 3 条请求 */
const CLOCK_STEP_MS = 20_000;

const fails = [];
const check = (cond, msg) => { if (!cond) fails.push(msg); };
const note = (s) => console.log(`   ${s}`);

function startTarget() {
  const sessions = {
    // 认证面
    authOk: 0, auth401: 0, rejectedExpired: 0, rejectedNoToken: 0, rejectedBadSig: 0,
    // 业务面（只有验签通过才会走到这里）
    reachedSql: 0, reachedPayload: 0,
    // 续期面（靶站自己数的 —— 引擎说"我续期成功了"不算，这里要看到端点真的被打过）
    refreshHits: 0, refreshOk: 0, refreshFailed: 0, issued: 0,
    // 「过期之后仍试图打进来的注入数」—— A/C 场景的核心裁判：> 0 就说明有整段检测
    // 是在没有认证的情况下跑的
    payloadAfterExpired: 0,
    lastAuthWhy: '',
  };
  const state = { nowMs: Date.now(), cookieIssued: false, broken: 'none', tokenMode: 'good', seq: 0 };
  let db;
  let server;
  let initialToken = '';

  const runRaw = (sql) => {
    try {
      const res = db.exec(sql);
      if (!res.length) return { rows: [] };
      const cols = res[0].columns;
      return { rows: res[0].values.map((row) => Object.fromEntries(cols.map((c, i) => [c, row[i]]))) };
    } catch (e) {
      return { error: String(e.message || e) };
    }
  };
  const runBound = (sql, params) => {
    const stmt = db.prepare(sql);
    try {
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      return { rows };
    } catch (e) {
      return { error: String(e.message || e) };
    } finally {
      stmt.free();
    }
  };

  const json = (res, status, obj, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
    res.end(JSON.stringify(obj));
  };
  /** 业务页：报错与空结果都回 200 并把原因写在页面里（真靶站常见形态，也是引擎 error 技术的素材） */
  const page = (res, html, extra = {}) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...extra });
    res.end(html);
  };

  const looksLikePayload = (v) => /'|--|;|\bOR\b|\bAND\b|UNION|SLEEP|information_schema/i.test(String(v || ''));

  function readBody(req) {
    return new Promise((resolve) => {
      let buf = '';
      req.on('data', (c) => (buf += c));
      req.on('end', () => resolve(buf));
    });
  }

  const handleRefresh = async (req, res, url) => {
    sessions.refreshHits += 1;
    const body = await readBody(req);
    if (state.broken === '5xx') {
      sessions.refreshFailed += 1;
      return json(res, 500, { error: 'auth_service_unavailable' });
    }
    if (state.broken === 'no-token-field') {
      // 200 + 结构合法但**没有可用令牌**：配错 tokenField 的真实形态（不是故意刁难，
      // 很多网关在 grant 被拒时也回 200 业务码）
      sessions.refreshFailed += 1;
      return json(res, 200, { code: 0, msg: 'grant accepted but token store unavailable' });
    }
    // 刷新凭据：body 里的 refreshToken / 或 Cookie（两条都支持，对应两种真实实现）
    let presented = '';
    try {
      const j = JSON.parse(body || '{}');
      presented = String(j.refreshToken || j.refresh_token || '');
    } catch {
      const sp = new URLSearchParams(body || '');
      presented = String(sp.get('refreshToken') || sp.get('refresh_token') || '');
    }
    const cookie = String(req.headers.cookie || '');
    const cookieRt = /(?:^|;\s*)refresh=([^;]+)/.exec(cookie)?.[1] || '';
    if (!presented && cookieRt) presented = cookieRt;
    if (presented !== REFRESH_SECRET) {
      sessions.refreshFailed += 1;
      return json(res, 400, { error: 'invalid_grant', got: presented ? 'mismatch' : 'none' });
    }
    state.seq += 1;
    // 续期换来的那枚给**长有效期**：本套件要测的是"续期这件事有没有接上"，
    // 不是"令牌多久坏一次"。短 TTL 会让引擎每 3 条续一次期，把 A/B 的差别淹成同一种纹理。
    const token = signToken(state.nowMs, state.seq, REFRESHED_TTL_MS);
    sessions.issued += 1;
    sessions.refreshOk += 1;
    // 嵌套一层：逼引擎按 tokenField 取（默认兜底列表里 data.access_token 也在，故 B 场景可不配）
    return json(res, 200, { code: 0, msg: 'ok', data: { access_token: token, token_type: 'Bearer', expires_in: Math.floor(TOKEN_TTL_MS / 1000) } });
  };

  const handleApi = (req, res, url) => {
    // 会话面：靶站在**第一条**响应里下发 refresh cookie（真实实现的形状：登录响应带
    // Set-Cookie: refresh_token=…，之后续期只靠它）。
    // ⚠ 不用 `--cookie` 静态塞：CLI 的 --cookie 会被当作「cookie 注入面」（cookieParams），
    //   由检测器逐请求拼 Cookie 头，而续期请求走的是 client.request 那条路、不经过检测器 ——
    //   于是静态 cookie 到不了刷新端点。真实世界靠会话 jar 携带，这里就照真实世界造。
    const issueCookie = !state.cookieIssued;
    if (issueCookie) state.cookieIssued = true;
    const setCookie = issueCookie ? { 'set-cookie': `refresh=${REFRESH_SECRET}; Path=/; HttpOnly` } : {};
    const auth = String(req.headers.authorization || '');
    const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (!m) {
      sessions.auth401 += 1;
      sessions.rejectedNoToken += 1;
      sessions.lastAuthWhy = 'no-token';
      return json(res, 401, { error: 'unauthorized', detail: 'missing bearer token' }, { 'WWW-Authenticate': 'Bearer error="invalid_token"', ...setCookie });
    }
    const v = verifyToken(m[1], state.nowMs);
    if (!v.ok) {
      sessions.auth401 += 1;
      if (v.why === 'expired') sessions.rejectedExpired += 1;
      if (v.why === 'bad-signature') sessions.rejectedBadSig += 1;
      sessions.lastAuthWhy = v.why;
      // 这条请求带的值如果本身是注入 payload，就是"白打了一次检测"的直接证据
      const val = url.searchParams.get('id');
      if (looksLikePayload(val)) sessions.payloadAfterExpired += 1;
      return json(res, 401, { error: 'unauthorized', detail: v.why }, { 'WWW-Authenticate': `Bearer error="invalid_token", error_description="${v.why}"`, ...setCookie });
    }
    sessions.authOk += 1;
    const id = url.searchParams.get('id');
    const safe = url.pathname.startsWith('/api/safe-item');
    if (looksLikePayload(id)) sessions.reachedPayload += 1;
    sessions.reachedSql += 1;
    if (safe) {
      const r = runBound('SELECT id, name, price FROM items WHERE id = ?', [Number(id) || 0]);
      const body = r.error ? `<p>${r.error}</p>` : `<p>${r.rows.map((x) => x.name).join(', ') || 'no rows'}</p>`;
      return page(res, `<h1>Safe Item</h1>${body}`, setCookie);
    }
    // 可注入：字符串直接拼进 SQL（真靶站的形状），报错写在 200 页面里
    const r = runRaw(`SELECT id, name, price FROM items WHERE id = ${id}`);
    const body = r.error ? `<p>查询失败: ${r.error}</p>` : `<p>${r.rows.map((x) => `${x.name}=${x.price}`).join(', ') || 'no rows'}</p>`;
    return page(res, `<h1>Item View</h1>${body}`, setCookie);
  };

  const handle = async (req, res) => {
    const url = new URL(req.url, 'http://lab.local');
    if (url.pathname === '/oauth/token') return handleRefresh(req, res, url);
    if (url.pathname === '/api/item' || url.pathname === '/api/safe-item') {
      // 虚拟时钟：每条业务请求拨快一格 ⇒ 令牌必然在扫描中途过期（与 CI 快慢无关）
      state.nowMs += CLOCK_STEP_MS;
      return handleApi(req, res, url);
    }
    if (url.pathname === '/lab/initial-token') return json(res, 200, { token: initialToken });
    return json(res, 404, { error: 'not_found' });
  };

  const ready = (async () => {
    const { loadSqlJs } = await import(pathToFileURL(path.join(ROOT, 'server', 'src', 'core', 'sqlJsLoader.js')).href);
    const initSqlJs = await loadSqlJs();
    const SQL = await (typeof initSqlJs === 'function' ? initSqlJs({}) : initSqlJs);
    db = new SQL.Database();
    db.run(SEED);
    initialToken = signToken(state.nowMs, 0); // seq 0 = "抓包里带来的那一枚"
    server = http.createServer(handle);
    const port = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
    return port;
  })();

  return {
    ready,
    sessions,
    state,
    get initialToken() { return initialToken; },
    reset() {
      sessions.authOk = 0; sessions.auth401 = 0; sessions.rejectedExpired = 0;
      sessions.rejectedNoToken = 0; sessions.rejectedBadSig = 0;
      sessions.reachedSql = 0; sessions.reachedPayload = 0;
      sessions.refreshHits = 0; sessions.refreshOk = 0; sessions.refreshFailed = 0; sessions.issued = 0;
      sessions.payloadAfterExpired = 0;
      sessions.lastAuthWhy = '';
      state.nowMs = Date.now();
      state.broken = 'none';
      state.tokenMode = 'good';
      state.seq = 0;
      // ⚠ 必须复位：refresh cookie 只在**每轮第一条**响应里下发（真实实现的形状）。
      //   不复位则第二轮起靶站再也不发 cookie，D 场景的"靠 jar 携带刷新凭据"就静默测不到东西
      //   —— 实测过一次的失败形态是 refresh 全 400 + 报告 session_expired，看着像引擎坏了。
      state.cookieIssued = false;
      // D 场景全靠这条：靶站每轮**重新下发** refresh cookie（引擎侧的会话 jar 是 per-scan 的，
      // 上一轮存的那份跟着扫描回收了；这里不重发，D 就只能拿到 400 invalid_grant）
      state.cookieIssued = false;
      // 每轮都重新签发：上一轮的令牌在虚拟时钟里已经"过期"了
      initialToken = signToken(state.nowMs, 0);
    },
    stop: () => new Promise((r) => server.close(r)),
  };
}

function runCli(args, envExtra = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(ROOT, 'server', 'bin', 'cli.js'), ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', ...envExtra },
    });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.once('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

const target = startTarget();
const port = await target.ready;
const base = `http://127.0.0.1:${port}`;
const outDir = path.join(ROOT, 'logs', 'bearer-lab-out');
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const COMMON = [
  '--level', '1', '--risk', '1', '--technique', 'error,boolean',
  '--rate', '0', '--req-rate', '0', '--timeout', '60000', '--format', 'json',
];

/**
 * 跑一轮并抽取本套件关心的事实。
 * 计数取自 report.validity.counts.refresh（判据成立那一刻的冻结快照），
 * 靶站侧计数取自 target.sessions（**独立裁判**：引擎自报"续期成功"不算，端点要真的被打过）。
 */
async function scenario(name, { urlPath = '/api/item?id=1', refresh = false, broken = 'none', extraArgs = [], cookie = false } = {}) {
  const o = path.join(outDir, `${name}.json`);
  target.reset();
  target.state.broken = broken;
  const before = { ...target.sessions };
  const args = ['-u', `${base}${urlPath}`, '--header', `Authorization: Bearer ${target.initialToken}`, '--out', o, ...COMMON, ...extraArgs];
  if (refresh) {
    args.push('--refresh-url', `${base}/oauth/token`);
    // cookie=false：刷新凭据走 body（--refresh-token）
    // cookie=true ：什么都不配 —— 凭据只能从会话 jar 里来（靶站用 Set-Cookie 下发），
    //               这才是"引擎自己把 cookie 带进刷新端点"那条路
    if (!cookie) args.push('--refresh-token', REFRESH_SECRET);
  }
  const r = await runCli(args);
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(o, 'utf8'));
  } catch { /* 报告缺失由下面的断言兜住 */ }
  const s = target.sessions;
  const d = (k) => s[k] - before[k];
  const out = {
    name,
    code: r.code,
    stderr: r.stderr,
    report,
    verdict: report?.summary?.verdict ?? '(无报告)',
    status: report?.validity?.status ?? '(无 validity)',
    reason: report?.validity?.reason ?? '',
    advice: report?.validity?.advice ?? '',
    reliable: report?.validity?.reliable ?? null,
    refreshCounts: report?.validity?.counts?.refresh ?? null,
    vulns: (report?.vulns || []).length,
    total: report?.validity?.counts?.total ?? 0,
    lab: {
      authOk: d('authOk'), auth401: d('auth401'), expired: d('rejectedExpired'),
      noToken: d('rejectedNoToken'), reachedSql: d('reachedSql'), reachedPayload: d('reachedPayload'),
      refreshHits: d('refreshHits'), refreshOk: d('refreshOk'), issued: d('issued'),
      payloadAfterExpired: d('payloadAfterExpired'),
    },
    raw: report,
  };
  note(`${name}: 退出码=${r.code} verdict=${out.verdict} validity=${out.status} 检出=${out.vulns} `
    + `| 靶站: 认证通过=${out.lab.authOk} 401=${out.lab.auth401}(过期 ${out.lab.expired}) `
    + `抵达SQL=${out.lab.reachedSql} 其中注入=${out.lab.reachedPayload} 续期请求=${out.lab.refreshHits}(成功 ${out.lab.refreshOk}, 发新令牌 ${out.lab.issued}) `
    + `过期后被拒的注入=${out.lab.payloadAfterExpired}`);
  if (out.refreshCounts) {
    note(`   ${name}: 引擎侧 refresh=${JSON.stringify(out.refreshCounts)}`);
  }
  return out;
}

// ============================================================================
// A 对照组：只带抓包里的 Bearer、不配续期 —— 把"不做这半程"的形态钉成事实
// ============================================================================
// ⚠ 期望值不是"报告自认正常"，而是"报告必须承认这半程没测"。这两件事在 D36 之前是反的：
//   既有 authLost 判据要求「注入请求 401 而基线请求没有」，而令牌过期时**基线同样吃 401**
//   ⇒ 反证恒成立 ⇒ 那条判据在这类目标上永不可达（与 D35 的 transform_rejected「单点+早剪
//   目标上不可达」是同一类失效）。expiredMidScan 补的就是这一格。
note('— A 对照组：不配 --refresh-url（后半程全部白打）');
const A = await scenario('A');
check(A.lab.authOk >= 1, `A: 抓包带来的凭据必须真的到得了靶站（0 次认证通过 = CLI 认证链又断了，见 models.js 的 D36 修复）`);
check(A.lab.expired >= 1, `A: 靶站应当真的把令牌判过期（否则这轮没测到"过期"这件事），实得过期拒 ${A.lab.expired}`);
check(A.lab.refreshHits === 0, `A: 没配续期就不该打刷新端点，实得 ${A.lab.refreshHits} 次`);
check(A.lab.payloadAfterExpired >= 1, `A: 过期后应当仍有注入白打（这就是静默假阴性的现场），实得 ${A.lab.payloadAfterExpired}`);
check((A.refreshCounts?.attempts ?? -1) === 0, `A: 引擎侧续期计数必须为 0，实得 ${JSON.stringify(A.refreshCounts)}`);
check(A.status === 'session_expired', `A: 会话中途失效必须被认出来，实得 ${A.status}`);
check(A.reliable === false, `A: 这种半程失效的扫描不可信，实得 reliable=${A.reliable}`);
check(A.verdict === 'inconclusive', `A: verdict 必须是 inconclusive，实得 ${A.verdict}`);
check(/连续 \d+ 次/.test(A.reason) && /扫描进行中失效/.test(A.reason), `A: reason 要说清"进去过、后来出不去"，实得 ${A.reason}`);
check(A.reason.includes('已配 Bearer 自动续期') === false, `A: 没配续期不得说配过，实得 ${A.reason}`);
check(/--refresh-url|config\.bearerRefresh|--login-url/.test(A.advice), `A: 建议必须给出自动续期/自动重登的出路，实得 ${A.advice}`);
note(`   A 的可信度落点：status=${A.status} reliable=${A.reliable} verdict=${A.verdict}`);

// ============================================================================
// B 配续期：过期后自动换新令牌 ⇒ 注入照样抵达 SQL、照样检出
// ============================================================================
note('— B：配 --refresh-url + --refresh-token（body 形态）');
const B = await scenario('B', { refresh: true });
check(B.lab.refreshHits >= 1, `B: 靶站必须收到过续期请求，实得 ${B.lab.refreshHits}`);
check(B.lab.issued >= 1, `B: 续期必须真的换到了新令牌，实得签发 ${B.lab.issued} 枚`);
check(B.lab.authOk > B.lab.expired * 0.5, `B: 大多数请求应在已认证态完成（认证通过 ${B.lab.authOk} vs 过期拒 ${B.lab.expired}）`);
check(B.lab.expired <= B.lab.refreshHits * 2 + 2,
  `B: 每次挑战至多换来一次续期；过期拒 ${B.lab.expired} 远多于续期次数 ${B.lab.refreshHits} = 新令牌没真的用上去`);
check(B.lab.reachedPayload > A.lab.reachedPayload, `B: 抵达 SQL 的注入必须多于对照组（${B.lab.reachedPayload} vs ${A.lab.reachedPayload}）`);
check(B.vulns >= 1, `B: 可注入点应被检出，实得 ${B.vulns} 条（verdict=${B.verdict}）`);
check(B.verdict === 'vulnerability_detected', `B: verdict 应为 vulnerability_detected，实得 ${B.verdict}`);
check(B.status !== 'session_expired', `B: 会话被维持住了，不该判会话过期，实得 ${B.status}`);
check((B.refreshCounts?.successes ?? 0) >= 1, `B: 引擎侧应记录续期成功，实得 ${JSON.stringify(B.refreshCounts)}`);
check((B.refreshCounts?.failures ?? 1) === 0, `B: 这个场景续期不该失败，实得 ${JSON.stringify(B.refreshCounts)}`);

// ============================================================================
// C1/C2 续期失败的两条形态 ⇒ 结论必须降级且**指名道姓**
// ============================================================================
note('— C1：续期端点 5xx');
const C1 = await scenario('C1', { refresh: true, broken: '5xx' });
note('— C2：续期端点 200 但响应里没有可用 token（字段配歪的真实形态）');
const C2 = await scenario('C2', { refresh: true, broken: 'no-token-field' });

for (const [nm, sc] of [['C1', C1], ['C2', C2]]) {
  check(sc.lab.refreshHits >= 1, `${nm}: 续期端点应被打到，实得 ${sc.lab.refreshHits}`);
  check(sc.lab.issued === 0, `${nm}: 这个场景里不该换到新令牌，实得 ${sc.lab.issued}`);
  check(sc.reliable === false, `${nm}: 续期失败后的阴性结论不可信，实得 reliable=${sc.reliable}`);
  check(
    sc.verdict === 'inconclusive' || sc.status === 'blocked' || sc.status === 'session_expired',
    `${nm}: 绝不能落成 no_vulnerability_detected，实得 verdict=${sc.verdict} status=${sc.status}`,
  );
  check(sc.verdict !== 'no_vulnerability_detected', `${nm}: 静默假阴性现场！verdict=${sc.verdict}`);
  check(/续期|bearerRefresh/.test(`${sc.reason}${sc.advice}`), `${nm}: 文案必须指向续期链路，实得 reason=${sc.reason} advice=${sc.advice}`);
  check(sc.reason.includes('已配 Bearer 自动续期'), `${nm}: reason 必须说"本次配过续期"，实得 ${sc.reason}`);
  check(/bearerRefresh\.url|tokenField/.test(sc.advice), `${nm}: advice 要指到具体键名，实得 ${sc.advice}`);
}
// C1 端点自己 5xx：reason 里要带最后一次失败原因（这是"配错 vs 目标故障"的唯一线索）
check(C1.reason.includes('500'), `C1: reason 要给出失败原因（端点状态码），实得 ${C1.reason}`);
// C2 的 why 必须把"试过哪些字段 + 响应顶层有什么键"说出来 —— 配错字段名是这类配置最常见的错
check(/没有可用 token/.test(C2.reason) && /响应顶层键=code,msg/.test(C2.reason),
  `C2: reason 要给出可诊断的取 token 失败细节，实得 ${C2.reason}`);

// ============================================================================
// D 刷新凭据只在 Cookie 里（不配 --refresh-token）
// ============================================================================
note('— D：刷新凭据走会话 Cookie');
const D = await scenario('D', { refresh: true, cookie: true });
check(D.lab.refreshHits >= 1, `D: 靠 cookie 取刷新凭据也要真的续上，实得续期请求 ${D.lab.refreshHits} 次`);
check(D.lab.issued >= 1, `D: 应签发新令牌，实得 ${D.lab.issued}`);
check(D.status !== 'session_expired', `D: 会话维持住了就不该判过期，实得 ${D.status}`);

// ============================================================================
// SAFE 安全对照点：参数化查询 + 配续期 ⇒ 0 检出（证明 B 的检出不是靶站白送）
// ============================================================================
note('— SAFE 对照：参数化查询的同类接口（配续期）');
const SAFE = await scenario('SAFE', { urlPath: '/api/safe-item?id=1', refresh: true });
check(SAFE.vulns === 0, `SAFE: 参数化查询接口不应有检出，实得 ${SAFE.vulns} 条`);
check(SAFE.lab.refreshHits >= 1, `SAFE: 这轮同样要真的把令牌续上（否则 0 检出只是因为没测），实得 ${SAFE.lab.refreshHits}`);
check(SAFE.lab.reachedSql >= 5, `SAFE: 检测请求应抵达 SQL，实得 ${SAFE.lab.reachedSql}`);
check(SAFE.verdict === 'no_vulnerability_detected' && SAFE.reliable === true,
  `SAFE: 会话维持 + 真的测过 ⇒ 阴性结论才允许成立，实得 verdict=${SAFE.verdict} reliable=${SAFE.reliable} status=${SAFE.status}`);

// ============================================================================
// 摘掉实现看是否变红（防"这套断言其实白送"）：本文件不改动生产代码，
// 由 run.mjs 的 --break-chain 开关**把续期配置摘掉**跑一遍 B 的场景，
// 期望它的检出与抵达 SQL 掉回对照组水平。
// ============================================================================
if (process.argv.includes('--break-chain')) {
  note('— 变异：同一条链路但**摘掉 --refresh-url**（等价于把 withBearerRefresh 从链上摘掉）');
  const Bx = await scenario('Bx', { refresh: false });
  // 判据方向：摘掉续期 ⇒ 检出必须掉回对照组（实测 B=2 条 / Bx=0 条，三轮连跑数字逐位一致）。
  // 用 `< B.vulns` 而不是 `=== 0`：掉多少取决于检测器在过期前跑到第几个 payload，
  // 而"有没有掉"才是这条差分要回答的问题。
  check(Bx.vulns < B.vulns, `摘掉续期后检出必须下降（B ${B.vulns} 条 → Bx ${Bx.vulns} 条），否则 B 的证据是白送的`);
  check(Bx.lab.payloadAfterExpired >= 1,
    `Bx 应当出现"过期后白打的注入"（实得 ${Bx.lab.payloadAfterExpired}）—— 这是这半程存在的唯一理由`);
  check(Bx.lab.refreshHits === 0, `变异轮不该打续期端点，实得 ${Bx.lab.refreshHits}`);
}

const table = [A, B, C1, C2, D, SAFE];
// 靶站必须在这里之前关掉：server.listen 不退的话 process.exit 之前的任何 await 都会挂住
await target.stop();
console.log('\n[bearer-lab] 实测计数（供后续阈值/文案回定）：');
for (const x of table) {
  console.log(`   ${x.name}: status=${x.status} reliable=${x.reliable} verdict=${x.verdict} `
    + `引擎refresh=${JSON.stringify(x.refreshCounts)} 靶站=${JSON.stringify(x.lab)} 总请求=${x.total}`);
}

if (fails.length) {
  console.error(`[FAIL] Bearer 续期靶场（bearer-lab）：\n  - ${fails.join('\n  - ')}`);
  process.exit(1);
}
console.log(
  `[PASS] bearer-lab（${table.length} 场景）：A 无续期=过期后 ${A.lab.payloadAfterExpired} 条注入白打（status=${A.status}）`
  + ` / B 续期成功=${B.lab.refreshOk} 次、抵达 SQL 注入 ${B.lab.reachedPayload} 条、检出 ${B.vulns} 条`
  + ` / C1 端点5xx 与 C2 无字段 均落 ${C1.verdict}（reason 指向续期链路）`
  + ` / D cookie 形态续上 ${D.lab.issued} 枚 / SAFE 0 检出且真的测过（${SAFE.lab.reachedSql} 条抵达 SQL）`,
);
process.exit(0);

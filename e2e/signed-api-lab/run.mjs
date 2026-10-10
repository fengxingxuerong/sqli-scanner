// ============================================================================
// e2e/signed-api-lab/run.mjs —— 签名/加密参数接口的真机验收（批次 D34，收 D32 的账 1）
//
// D32 交的是「扩展点 + 判据」，但全部证据是单元与接线级 —— 仓库里没有带签名参数的靶点，
// 于是这两句话长期没有实弹背书：
//   ① 「正确签名能把注入送到 SQL」；
//   ② 「签名不对时报的是 inconclusive，而不是未检出」。
// 本套件用**真 SQL 引擎（sql.js/SQLite）+ 真 HTTP 靶站 + 真 CLI 进程 + 真签名校验**把这两句
// 变成可回归的事实，并顺手把 D32 里两个**拍出来的阈值**换成实测分布。
//
// 五个场景，缺一个就有一类结论站不住：
//   D 对照组（**先跑**）：不带签名脚本 ⇒ 每条请求都被目标拒。断言它当下的形态是
//     「0 检出 + verdict=no_vulnerability_detected + reliable=true」——
//     把「不做这个扩展点会怎样」钉成事实，而不是留一句"会漏"给人争论。
//   A 正确脚本 ⇒ 真检出 + 安全对照点 0 检出 + 报告自动标注脚本与 sha256 + 不出 transform_rejected。
//   B 字段集算错（漏掉被注入的 id）⇒ transform_rejected(kind='injection')。
//   C 密钥错 ⇒ transform_rejected(kind='baseline')，且**总请求数显著少于 A**（早停真的生效）。
//   E 混合目标（正确签名，但只有含 union 的取值被输入过滤拦 ⇒ 天然有一批 4xx）⇒
//     **不许**误报 transform_rejected。这条是阈值的反例防线：只看"被拒条数"就定罪会打它。
//
// 靶站侧计数是本套件真正的裁判：`reachedSql`（验签通过、真的拼进 SQL 的请求数）。
//   B/C 期望它恒 0 ⇒ 「检测从未开始」不是推测而是靶站记录；
//   A/E 期望它 > 0 ⇒ 否则 A 的检出是白送的（靶站根本没验签）。
// ============================================================================
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { KEY, buildSign, paramsOf } from './sign-scheme.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const SIGNERS = path.join(HERE, 'signers');

/** 目标只在 id 上可注入；t 是"业务字段"，一起进签名 */
const SEED = `CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price TEXT);
INSERT INTO items VALUES (1,'widget','$9.90'),(2,'gadget','$19.00'),(3,'doohickey','$5.00');`;

const fails = [];
const check = (cond, msg) => { if (!cond) fails.push(msg); };
const note = (s) => console.log(`   ${s}`);

/** 判据阈值的实测素材（每场景从报告的冻结快照里取） */
const measured = [];

function startTarget() {
  // 同步启动包装：sql.js 是异步加载，故外层用 async IIFE（见文件尾 await）
  const sessions = { signChecked: 0, signRejected: 0, reachedSql: 0, reachedPayload: 0, blockedByFilter: 0 };
  let db;
  let server;

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
  /** 参数化执行（安全对照点用它 —— 同一条 SQL 模板，唯一区别是值不拼进语句） */
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

  const reply = (res, status, obj) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
  };
  /**
   * 注入点/混合点的响应：**200 页面内回显 SQL 错误**（sqli-labs 的形态：PHP 把
   * mysqli_error() 直接印进页面）。
   *
   * ⚠️ 第一版这里用的是 500 + `{"error":"unrecognized token: X"}`，结果 prefilter 把两个靶点
   *   全剪掉了 —— 实测 `prefilterSimilar(单引号探针, 良性非法值探针) === true`：SQLite 的错误
   *   文本只回显肇事 token，`unrecognized token: "'"` 与 `unrecognized token: "1zz9qx0"`
   *   在判据眼里同构 ⇒ 被认定「是输入白名单在报错，不是 SQL 报错」⇒ 安全跳过。
   *   **prefilter 没错**，是靶站不像真实可注入目标：那种形态的报错确凿是弱信号。
   *   改成 200 页内回显后：状态码不 ≥400 ⇒ 不走那条甄别（见 prefilter OPT-FIX#2 的口径），
   *   基线与探针的正文差异照常保留完整检测。
   */
  const page = (r) => {
    const body = r.error
      ? `<p>Query failed: ${r.error}</p>`
      : `<ul>${r.rows.map((x) => `<li>${x.id}|${x.name}|${x.price}</li>`).join('')}</ul>`;
    return `<html><body><h3>items</h3>${body}</body></html>`;
  };
  const html = (res, s) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(s);
  };

  const handle = (req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const route = u.pathname;
    if (!['/api/item', '/api/safe', '/api/mixed'].includes(route)) return reply(res, 404, { msg: 'no such api' });

    const got = String(u.searchParams.get('sign') || '');
    const want = buildSign(paramsOf(req.url), KEY);
    sessions.signChecked += 1;
    // ★ 验签在最前面：签名不对 ⇒ 业务代码根本不执行（真实网关/框架中间件就是这个位置）
    if (got !== want) {
      sessions.signRejected += 1;
      return reply(res, 400, { code: 4001, msg: 'sign invalid' });
    }
    const id = String(u.searchParams.get('id') ?? '1');
    /** 抵达 SQL 的请求里，取值已被改动的（=注入请求）单独计数：B/C 的裁判就是这个数 */
    const markReached = () => {
      sessions.reachedSql += 1;
      if (id !== '1') sessions.reachedPayload += 1;
    };

    if (route === '/api/safe') {
      markReached();
      const r = runBound('SELECT id,name,price FROM items WHERE id = ?', [Number.isFinite(Number(id)) ? Number(id) : -1]);
      return reply(res, 200, { items: r.error ? [{ error: r.error }] : r.rows });
    }
    if (route === '/api/mixed') {
      // 朴素的"关键字过滤"：只看值里有没有 union/select —— 签名合法也会被拒，
      // 而其它 payload（布尔/报错）正常进 SQL ⇒ 制造"有 4xx 但检测确实在跑"的形态
      if (/union|select/i.test(id)) {
        sessions.blockedByFilter += 1;
        return reply(res, 400, { code: 4002, msg: 'illegal keyword in parameter' });
      }
      markReached();
      return html(res, page(runRaw(`SELECT id,name,price FROM items WHERE id = ${id}`)));
    }
    // /api/item：数值上下文直接拼接 —— 真注入点
    markReached();
    return html(res, page(runRaw(`SELECT id,name,price FROM items WHERE id = ${id}`)));
  };

  const ready = (async () => {
    const { loadSqlJs } = await import(pathToFileURL(path.join(ROOT, 'server', 'src', 'core', 'sqlJsLoader.js')).href);
    const initSqlJs = await loadSqlJs();
    const SQL = await (typeof initSqlJs === 'function' ? initSqlJs({}) : initSqlJs);
    db = new SQL.Database();
    db.run(SEED);
    server = http.createServer(handle);
    const port = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
    return port;
  })();

  return {
    ready,
    sessions,
    reset() {
      sessions.signChecked = 0;
      sessions.signRejected = 0;
      sessions.reachedSql = 0;
      sessions.reachedPayload = 0;
      sessions.blockedByFilter = 0;
    },
    stop: () => new Promise((r) => server.close(r)),
  };
}

function runCli(args, envExtra = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(ROOT, 'server', 'bin', 'cli.js'), ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      // REQUEST_SCRIPT_DIR 必须给**子进程**：脚本白名单根由加载它的那个进程读
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
const outDir = path.join(ROOT, 'logs', 'signed-api-lab-out');
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const COMMON = [
  '--level', '1', '--risk', '1', '--technique', 'union,error,boolean',
  '--rate', '0', '--req-rate', '0', '--timeout', '60000', '--format', 'json',
];

/**
 * 跑一轮并抽取本套件关心的事实。
 * 计数一律取自 report.validity.counts.transform —— 那是**判据成立那一刻**的冻结快照
 * （scanValidityGuard 在状态成立时 _counters() 落一份），正是阈值标定要的数。
 */
async function scenario(name, { urlPath, signer, expectReport = true }) {
  const o = path.join(outDir, `${name}.json`);
  const args = ['-u', `${base}${urlPath}`, '--out', o, ...COMMON];
  const env = {};
  if (signer) {
    env.REQUEST_SCRIPT_DIR = SIGNERS;
    args.push('--request-script', path.join(SIGNERS, signer));
  }
  target.reset();
  const before = { ...target.sessions };
  const r = await runCli(args, env);
  const reached = target.sessions.reachedSql - before.reachedSql;
  const reachedPayload = target.sessions.reachedPayload - before.reachedPayload;
  const rejected = target.sessions.signRejected - before.signRejected;
  const checked = target.sessions.signChecked - before.signChecked;
  let rep = null;
  if (fs.existsSync(o)) {
    try {
      rep = JSON.parse(fs.readFileSync(o, 'utf8'));
    } catch (e) {
      check(false, `${name}: 报告不是合法 JSON（${e.message}）`);
    }
  }
  check(!expectReport || !!rep, `${name}: 应有报告落盘（${o}）；stderr 尾部：${r.stderr.slice(-400)}`);
  const v = rep?.validity || rep?.summary?.validity || {};
  const t = v.counts?.transform || {};
  const out = {
    name,
    code: r.code,
    vulns: (rep?.vulns || []).length,
    points: (rep?.points || []).length,
    verdict: String(rep?.summary?.verdict || ''),
    status: String(v.status || ''),
    reliable: v.reliable,
    kind: t.kind ?? null,
    total: Number(v?.counts?.total ?? 0),
    transform: t,
    constraints: (rep?.summary?.constraints || []).join(' | '),
    lab: { checked, rejected, reached, reachedPayload, blocked: target.sessions.blockedByFilter - before.blockedByFilter },
  };
  measured.push(out);
  note(
    `${name}：退出码=${out.code} 检出=${out.vulns} 点=${out.points} verdict=${out.verdict || '-'} `
    + `status=${out.status || '-'} kind=${out.kind ?? '-'} 请求总数=${out.total}｜`
    + `靶站：验签 ${checked} 次/拒 ${rejected} 次/抵达 SQL=${reached}（其中改了取值的注入请求 ${reachedPayload}）`,
  );
  if (out.status === 'transform_rejected' || out.verdict === 'inconclusive') {
    note(`   transform 计数（判据成立那一刻）：${JSON.stringify(t)}`);
  }
  return out;
}

// ============================================================================
// D 对照组（**先跑**）：不带签名脚本 ⇒ 目标把所有请求当非法
// 断言的是"现状有多难看"：0 检出 + verdict 写成 no_vulnerability_detected + reliable=true。
// 这条如果哪天变成 inconclusive（说明无签名场景也能被识别），就把期望改成新的正确形态。
// ============================================================================
note('— D 对照组：不带 --request-script（把静默假阴性钉成事实）');
const D = await scenario('D-control', { urlPath: '/api/item?id=1&t=1' });
check(D.lab.reached === 0, `D: 不带脚本时不应有任何请求抵达 SQL，实得 ${D.lab.reached} —— 靶站没在验签？`);
check(D.vulns === 0, `D: 不带脚本应当 0 检出，实得 ${D.vulns}`);
check(
  D.verdict === 'no_vulnerability_detected',
  'D: 本场景要钉的是「不做扩展点时的失效形态」——当前实现下每条请求都被拒、'
  + `而结论层没有任何东西变红。实得 verdict=${D.verdict || '(空)'} / status=${D.status}。`
  + '若这里变成 inconclusive，说明无签名场景也被识别了（更好），改期望并同步文档',
);

// ============================================================================
// A 正确签名：注入必须真的抵达 SQL 并被检出（+ 安全对照点必须 0 检出）
// ============================================================================
note('— A 正确签名脚本（同一套方案、对当前真实参数集签名）');
const A = await scenario('A-correct', { urlPath: '/api/item?id=1&t=1', signer: 'sign-correct.mjs' });
check(A.lab.reachedPayload > 0, `A: 正确签名下应有**被改过取值的注入请求**抵达 SQL，实得 ${A.lab.reachedPayload} —— 签名脚本没生效？`);
check(A.vulns > 0, `A: 正确签名下必须检出（这是整条链路的正面证据），实得 ${A.vulns}`);
check(
  A.status !== 'transform_rejected',
  `A: 签名正确时不得判被拒，实得 status=${A.status}（transform=${JSON.stringify(A.transform)}）`,
);
check(
  /自定义变换脚本/.test(A.constraints) && /sha256=/.test(A.constraints),
  `A: 报告必须自动标注启用了脚本（含 sha256 与 PoC curl 警示），实得 constraints="${A.constraints || '(空)'}"`,
);

const ASafe = await scenario('A-safe-control', { urlPath: '/api/safe?id=1&t=1', signer: 'sign-correct.mjs' });
check(
  ASafe.vulns === 0,
  `A-safe: 参数化查询的安全对照点必须 0 检出，实得 ${ASafe.vulns} —— `
  + '若这里报了洞，说明"检出"来自签名脚本之外的东西（靶站或判据有问题）',
);

// ============================================================================
// B 字段集算错：基线过、注入全挂 ⇒ kind='injection'
// ============================================================================
note('— B 签名只覆盖抓包时那份参数副本（漏掉被注入的 id）');
const B = await scenario('B-partial-fields', { urlPath: '/api/item?id=1&t=1', signer: 'sign-partial-fields.mjs' });
// 裁判是 reachedPayload（**改了取值的请求**抵达 SQL 的次数）：
// B 的签名对「抓包那份副本」成立 ⇒ 基线（id 未变）能过验签，这是**正确行为**，
// 若断言 reached===0 就等于要求"基线也被拒"，那已经是 C 场景的形态了。
check(B.lab.reachedPayload === 0, `B: 注入请求不该抵达 SQL，实得 ${B.lab.reachedPayload}（基线抵达 ${B.lab.reached} 次是允许的）`);
check(B.vulns === 0, `B: 该场景必须 0 检出（注入从未送达），实得 ${B.vulns}`);
check(
  B.status === 'transform_rejected' && B.kind === 'injection',
  `B: 应判 transform_rejected(kind=injection)，实得 status=${B.status} kind=${B.kind ?? '(空)'}`,
);
check(B.verdict === 'inconclusive', `B: 结论必须是 inconclusive 而不是「未检出」，实得 ${B.verdict}`);

// ============================================================================
// C 密钥错：连基线都挂 ⇒ kind='baseline' + 早停（总请求数远小于 A）
// ============================================================================
note('— C 密钥错（字段集与算法都对，基线也被拒）');
const C = await scenario('C-wrong-key', { urlPath: '/api/item?id=1&t=1', signer: 'sign-wrong-key.mjs' });
check(C.lab.reached === 0, `C: 密钥错时不应有请求抵达 SQL，实得 ${C.lab.reached}`);
check(
  C.status === 'transform_rejected' && C.kind === 'baseline',
  `C: 应判 transform_rejected(kind=baseline)，实得 status=${C.status} kind=${C.kind ?? '(空)'}`,
);
check(C.verdict === 'inconclusive', `C: 结论必须是 inconclusive，实得 ${C.verdict}`);
check(
  C.total < A.total / 2,
  `C: 基线被拒应当**早停**（后面每条必然同样被拒）。实得 C=${C.total} 请求 vs A=${A.total} —— `
  + '早停没生效，白烧预算',
);

// ============================================================================
// E 反例防线：正确签名 + 只有部分取值被输入过滤拦（天然有一批 4xx）
//   ⇒ 不许误报 transform_rejected。只看"被拒条数"就定罪会打在这条上。
// ============================================================================
note('— E 混合目标（签名正确，但含 union 的取值被关键字过滤拦成 400）');
const E = await scenario('E-mixed-filter', { urlPath: '/api/mixed?id=1&t=1', signer: 'sign-correct.mjs' });
check(
  E.lab.blocked > 0,
  `E: 这条用例的价值在于"确实有一批注入被 400 拒了"。实测关键字过滤命中 ${E.lab.blocked} 次 `
  + '—— 若为 0，说明靶站的过滤没生效，本反例是空转',
);
check(
  E.status !== 'transform_rejected',
  `E: 健康扫描里天然存在的 4xx 不得判成签名被拒，实得 status=${E.status} kind=${E.kind ?? '(空)'}`,
);

await target.stop();

// ============================================================================
// 阈值实测表（D32 里那两个数是拍的：基线连续 2 次 / 注入累计 8 次）
// ============================================================================
console.log('\n[signed-api-lab] 判据成立那一刻的实测计数（供阈值回定）：');
for (const m of measured.filter((x) => x.status === 'transform_rejected')) {
  console.log(
    `   ${m.name}: kind=${m.kind} baselineRejectStreak=${m.transform.baselineRejectStreak} `
    + `baselineRejects=${m.transform.baselineRejects} baselineOk=${m.transform.baselineOk} `
    + `injectRejects=${m.transform.injectRejects} injectOk=${m.transform.injectOk} 总请求=${m.total}`,
  );
}
const healthyRejects = measured
  .filter((x) => x.status !== 'transform_rejected')
  .map((x) => `${x.name}: injectRejects=${x.transform.injectRejects ?? 0} injectOk=${x.transform.injectOk ?? 0}`);
console.log(`   健康/对照组未被判拒时的计数：${healthyRejects.join(' ｜ ')}`);

if (fails.length) {
  console.error(`[FAIL] 签名接口靶场（signed-api-lab）：\n  - ${fails.join('\n  - ')}`);
  process.exit(1);
}
console.log(
  `[PASS] signed-api-lab：D（无脚本）0 检出且结论自认"正常"＝静默假阴性现场；`
  + `A（正确脚本）检出 ${A.vulns} 条、抵达 SQL ${A.lab.reached} 次、安全点 0；`
  + `B kind=injection / C kind=baseline（C 早停：${C.total} < A ${A.total}/2）；E 不误报`,
);
process.exit(0);

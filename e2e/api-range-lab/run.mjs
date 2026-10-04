// ============================================================================
// e2e/api-range-lab/run.mjs —— 接口靶场入口（真 MySQL + 真靶站 + 真 HTTP 引擎）
//
// 回答的问题：**每一条对外接口，在真实靶场上是否把承诺的能力交付给了用户**。
// 与既有靶场的差异：其它 e2e 大多直接 import ScanManager 跑引擎（那验证的是引擎），
// 本套件只走 HTTP —— 入参守卫、状态码语义、SSE、鉴权、导出、利用、AI 外发，
// 这些"接口层"的东西只有真发一个 HTTP 请求才算被测到。
//
// 用法：
//   python e2e/run-with-sandbox.py e2e/api-range-lab/run.mjs          # 全套（需真库）
//   node e2e/api-range-lab/run.mjs --groups=meta,gates                # 只要无库依赖的组
//   node e2e/api-range-lab/run.mjs --list
//   node e2e/api-range-lab/run.mjs --only=exploit                      # 单组调试
// 依赖：MYSQL_* 由 run-with-sandbox.py 注入（默认 127.0.0.1:3308 root）
// 退出码：0=全绿；1=有失败（失败现场打印引擎日志尾部）
// ============================================================================
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRangeApp } from './range-app.mjs';
import { createMockLlmApp } from './mock-llm.mjs';
import { ROOT, freePort, mysqlConfFromEnv, mysql, request, startEngine } from './harness.mjs';
import CASES from './cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = (name) => {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split('=').slice(1).join('=') : null;
};
const has = (name) => argv.includes(`--${name}`);

if (has('list')) {
  for (const c of CASES) console.log(`${c.group.padEnd(8)} ${c.name}`);
  console.log(`\n合计 ${CASES.length} 条`);
  process.exit(0);
}

const groups = (flag('groups') || flag('only') || '').split(',').map((s) => s.trim()).filter(Boolean);
const selected = groups.length ? CASES.filter((c) => groups.includes(c.group)) : CASES;
// [2026-10-01] xml 组要打真靶站的 /soap 端点（真 MySQL），故与 scan 同级需要 DB
const needsDb = selected.some((c) => ['scan', 'exploit', 'enum', 'direct', 'ai', 'persist', 'xml', 'sqlmap'].includes(c.group)); // [F2 2026-10-03] sqlmap 组新增两条正向用例打 /num（真 MySQL 靶点）⇒ 需要 range-app

const pkgVersion = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const results = [];
let engine = null;
let labServer = null;
let llmServer = null;
let pool = null;

const fail = (msg) => {
  console.error(`\n[环境] ${msg}`);
  process.exit(needsDb ? 1 : 1);
};

try {
  // ── 1) 真库就绪（沙箱注入 MYSQL_*；缺库/缺表时先跑一次 init-db） ──
  const conf = mysqlConfFromEnv();
  if (needsDb) {
    try {
      const probe = await mysql.createConnection({ ...conf, connectionLimit: undefined, database: undefined });
      const [[{ n }]] = await probe.query(
        `SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = ? AND table_name IN ('users','products')`,
        [conf.database]
      );
      await probe.end();
      if (n < 2) {
        console.log('[env] 靶库缺表 → 执行 e2e/real-mysql-lab/init-db.mjs');
        await new Promise((resolve, reject) => {
          const c = spawn(process.execPath, [path.join(ROOT, 'e2e', 'real-mysql-lab', 'init-db.mjs')], { cwd: ROOT, stdio: 'inherit' });
          c.once('exit', (code) => (code === 0 ? resolve() : reject(new Error(`init-db 退出码 ${code}`))));
          c.once('error', reject);
        });
      }
    } catch (e) {
      fail(`无法连接靶库 ${conf.host}:${conf.port} —— 请用 python e2e/run-with-sandbox.py e2e/api-range-lab/run.mjs 运行。原因：${e.message}`);
    }
  }

  // ── 2) 靶站（真实 SQL 执行 + 流量取证） ──
  const labPort = await freePort();
  if (needsDb) {
    pool = mysql.createPool(conf);
    labServer = createRangeApp(pool).listen(labPort, '127.0.0.1');
    await new Promise((r) => labServer.once('listening', r));
  }
  const LAB = `http://127.0.0.1:${labPort}`;

  // ── 3) LLM 假端点（AI 报告接口的外发目标，只在回环） ──
  const llmPort = await freePort();
  llmServer = createMockLlmApp().listen(llmPort, '127.0.0.1');
  await new Promise((r) => llmServer.once('listening', r));

  // ── 4) 引擎（随机端口 + 一次性 token + 利用开启 + AI 指向假端点） ──
  // 台账指向 logs/ 下的专用目录：既不污染仓库里那份真台账，又能让用例直接翻文件核对
  const ledgerDir = path.join(ROOT, 'logs', 'api-range-ledger');
  fs.rmSync(ledgerDir, { recursive: true, force: true }); // 每轮从空台账开始，计数才有意义
  engine = await startEngine({
    name: 'api-range',
    env: {
      AI_REPORT_API_BASE: `http://127.0.0.1:${llmPort}/v1/chat/completions`,
      AI_REPORT_KEY_1: 'sk-mock-1',
      AI_REPORT_KEY_2: 'sk-mock-2',
      AI_REPORT_KEY_3: 'sk-mock-3',
      SQLI_LEDGER_DIR: ledgerDir,
      // [2026-10-01] 分钟级限流是**生产护栏**，但本套件一轮要起 40+ 次扫描 / 十几次利用，
      // 默认配额（10 次/分）必然把后半程打成 429 —— 表现是「用例大面积红」，而真相是
      // 护栏在正常工作、靶场没给它让路。故主实例显式放宽（env 与生产同源，不是旁路）。
      // ⚠️ 限速本身仍被专项用例钉住：那条用例起的是**独立实例**（EXPLOIT_RATE_PER_SEC=1），
      //    不受这里影响 —— 放宽配额不会把「限速有效」这条断言一起放掉。
      RATE_LIMIT_SCAN_MAX: '500',
      RATE_LIMIT_EXPLOIT_MAX: '500',
    },
  });
  console.log(`[env] 引擎 :${engine.port}  靶站 :${labPort}  LLM 假端点 :${llmPort}  token=***`);

  const llmGet = (p) => request({ port: llmPort, path: p });
  const llmPost = (p, body) => request({ port: llmPort, method: 'POST', path: p, body });
  const rangeGet = (p) => request({ port: labPort, path: p });
  const rangePost = (p, body) => request({ port: labPort, method: 'POST', path: p, body });

  const ctx = {
    engine,
    LAB,
    labPort,
    ledgerDir,
    llmPort,
    mysql: conf,
    pkgVersion,
    state: {},
    notes: {},
    note: (k, v) => {
      ctx.notes[k] = v;
    },
    get: (p, opts = {}) => request({ port: opts.port || engine.port, path: p, token: 'token' in opts ? opts.token : opts.port ? undefined : engine.token, ...opts }),
    post: (p, body, headers = {}, opts = {}) =>
      request({
        port: opts.port || engine.port,
        method: 'POST',
        path: p,
        body,
        headers,
        token: opts.token === undefined ? engine.token : opts.token,
        ...opts,
      }),
    rangeGet,
    rangePost,
    llmGet,
    llmPost,
    // 匿名变体：断言"不带凭据"是接口测试里最高频的形态，写成显式方法而不是
    // 靠 opts 里一个 undefined 的 token 键 —— 后者会被误传进 headers 位置，
    // 于是要么 Node 抛 Invalid value，要么带上 token 得到一个假通过。
    noAuthGet: (p, headers = {}) => request({ port: engine.port, path: p, headers }),
    noAuthPost: (p, body, headers = {}) => request({ port: engine.port, method: 'POST', path: p, body, headers }),
  };

  // ── 5) 逐条执行 ──
  const t0 = Date.now();
  for (const c of selected) {
    const name = `[${c.group}] ${c.name}`;
    if (c.skip) {
      results.push({ group: c.group, name: c.name, status: 'SKIP', reason: c.skipReason });
      console.log(`[SKIP] ${name} —— ${c.skipReason}`);
      continue;
    }
    const s = Date.now();
    try {
      await c.run(ctx);
      results.push({ group: c.group, name: c.name, status: 'PASS', ms: Date.now() - s });
      console.log(`[PASS] ${name}  (${((Date.now() - s) / 1000).toFixed(1)}s)`);
    } catch (e) {
      // 运行期才知道的跳过条件（如沙箱未注入 secure_file_priv）走 SKIP，
      // 但必须把理由打全 —— "缺前置"与"有缺陷"混在一起报，是门禁失去意义的开始。
      if (e && e.__skip) {
        results.push({ group: c.group, name: c.name, status: 'SKIP', reason: e.message, ms: Date.now() - s });
        console.log(`[SKIP] ${name} —— ${e.message}`);
        continue;
      }
      results.push({ group: c.group, name: c.name, status: 'FAIL', ms: Date.now() - s, error: e.message });
      console.log(`[FAIL] ${name}  (${((Date.now() - s) / 1000).toFixed(1)}s)`);
      console.log(`       ${String(e.message).split('\n').join('\n       ').slice(0, 1200)}`);
      if (process.env.API_RANGE_DEBUG) console.error(e.stack);
    }
  }

  const pass = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL');
  console.log(`\n[汇总] ${pass}/${results.length} PASS  用时 ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  for (const f of failed) console.log(`  ✗ [${f.group}] ${f.name}\n    ${f.error}`);

  if (process.env.API_RANGE_ENGINE_LOG_TAIL || failed.length) {
    try {
      const tail = fs.readFileSync(engine.logFile, 'utf8').split('\n').slice(-25).join('\n');
      console.log(`\n----- 引擎日志尾部 (${engine.logFile}) -----\n${tail}`);
    } catch {
      /* 日志读不到不影响结论 */
    }
  }

  fs.mkdirSync(path.join(HERE, 'out'), { recursive: true });
  fs.writeFileSync(
    path.join(HERE, 'out', 'api-range-report.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), engine: { port: engine.port }, lab: LAB, results, notes: ctx.notes }, null, 2)
  );
} finally {
  if (engine) await engine.stop();
  if (labServer) labServer.close();
  if (llmServer) llmServer.close();
  if (pool) await pool.end().catch(() => {});
}

process.exit(results.some((r) => r.status === 'FAIL') ? 1 : 0);

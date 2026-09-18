#!/usr/bin/env node
// CLI 模式（P1-U5）：无 UI 的命令行扫描入口，复用同一 ScanManager。
// 用法：
//   单目标：node bin/cli.js -u <url> [--method GET|POST] [--body '{"k":"v"}'] [--format json|html|csv|markdown]
//   直连：  node bin/cli.js -d "sqlite://test.db" --sql-template "SELECT * FROM t WHERE id={INJECT}"
//   批量：  node bin/cli.js -m <urls.txt> [--format json] [--concurrency 2]
// 事件经 eventBus 订阅转控制台进度输出，扫描结束打印报告到 stdout 并可按 --format 导出到文件。
import { ScanManager } from '../src/engine/ScanManager.js';
import * as eventBus from '../src/core/eventBus.js';
import { logger } from '../src/core/logger.js';
// 对标 sqlmap -r：解析 Burp/curl 文本请求文件（parseRequestFile 在 args.js 消费）
// 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）：复用引擎 Exploiter
import { Exploiter } from '../src/engine/Exploiter.js';
import { httpClient } from '../src/core/httpClient.js';
// [P1-FIX 2026-09-05] --format 出口：原为死参数（解析后从未消费，-o 恒写 JSON）。
// ReportGenerator 的 toCSV/toMarkdown/toHTML 与 REST /report/export 同源，直接复用。
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import * as scanLedger from '../src/services/scanLedger.js';
// [P0-SEC 2026-09-09] --scope 接线：CLI 直走 ScanManager 不经 scanRoutes，需在本层完成
// 「目标先校验 + 按 scanId 登记」，否则 --scope 是静默 no-op（httpClient 逐跳取用登记项）。
import { parseScope, assertInScope, registerScanScope, releaseScanScope } from '../src/core/scopeGuard.js';
import { printHelp } from './cli/help.js';
import {
  parseArgs,
  parseLogFile,
  resolveTamperPlugins,
  parseHeaders,
  bodyToJsonString,
  applyRequestFile,
  buildAuth,
  readUrlList,
  checkTor,
} from './cli/args.js';
import {
  buildInjectionTargets,
  buildConfig,
  isEnumMode,
  buildExtractScope,
  validateEnumArgs,
} from './cli/config.js';
// 再导出：8 个测试文件从 ../bin/cli.js 导入这些符号，路径不能变
export {
  parseArgs,
  parseLogFile,
  resolveTamperPlugins,
  parseHeaders,
  parseAuth,
  bodyToJsonString,
  applyRequestFile,
  buildAuth,
  readUrlList,
  checkTor,
} from './cli/args.js';

// --format 分发（json|csv|markdown|html）：单目标 -o 与批量目录导出共用。
// 未知格式回退 json（与 REST /report/export 的宽容行为一致）。
export function formatReport(report, fmt = 'json') {
  const f = String(fmt || 'json').toLowerCase();
  if (f === 'csv' || f === 'markdown' || f === 'md' || f === 'html') {
    const rg = new ReportGenerator();
    return f === 'csv' ? rg.toCSV(report)
      : f === 'html' ? rg.toHTML(report)
      : rg.toMarkdown(report);
  }
  if (f === 'sarif') {
    // [批次 9 2026-09-15] SARIF 2.1.0：GitHub Security / DefectDojo 对接
    return new ReportGenerator().toSARIF(report);
  }
  return JSON.stringify(report, null, 2);
}

// 极简参数解析（避免引入 commander 依赖）

// 对标 sqlmap --test-headers / --test-path（本期新增，默认关闭，零回归）：
// 把用户显式传入的请求头 / URL path 末段转为注入点。引擎 TargetParser 早已支持
// header/cookie/path 注入点（遍历 target.cookieParams / target.headerParams / path 段），
// 此前 CLI/解析层从未填充这些字段，导致带注入点的请求头（Cookie、X-Forwarded-For）与
// path 末段被完全跳过（危险假阴性）。
//
// --test-headers：把请求头（--header 或 -r 解析出的 headerObj）转为 target.headerParams；
//   Cookie 头特殊解析为 k=v 填入 target.cookieParams；host / content-length / content-type /
//   authorization 排除（传输层/认证类头，避免破坏请求或会话）。
// 返回 { headerParams?, cookieParams? }，供 runSingleScan 注入 target；无内容时返回 {}。

// 枚举模式精简文本输出（report.data 视图）
function printExtractView(report) {
  const data = report.data;
  if (!data) { console.log('（无提取数据，注入点未确认或提取失败）'); return; }
  if (data.currentDb !== undefined && data.currentDb !== null) console.log(`current database: ${data.currentDb}`);
  if (data.currentUser !== undefined && data.currentUser !== null) console.log(`current user: ${data.currentUser}`);
  if (data.users !== undefined && data.users !== null) console.log(`users: ${data.users}`);
  if (data.passwords !== undefined && data.passwords !== null) console.log(`passwords: ${data.passwords}`);
  if (data.hostname !== undefined && data.hostname !== null) console.log(`hostname: ${data.hostname}`);
  if (data.isDba !== undefined && data.isDba !== null) console.log(`is DBA: ${data.isDba}`);
  if (data.userPrivs !== undefined && data.userPrivs !== null) console.log(`privileges: ${data.userPrivs}`);
  if (data.roles !== undefined && data.roles !== null) console.log(`roles: ${data.roles}`);
  const hasTables = data.tables && Object.keys(data.tables).length;
  const hasCols = data.columns && Object.keys(data.columns).length;
  const hasRows = data.rows && Object.values(data.rows).some(v => Array.isArray(v) && v.length);
  const hasModeField = data.currentDb || data.currentUser || data.users || data.passwords || data.hostname || data.isDba || data.userPrivs || data.roles || (data.counts && Object.keys(data.counts).length);
  // --dbs：仅库名列表（其它模式不进入此分支）
  if (!hasTables && !hasCols && !hasRows && !hasModeField) {
    for (const db of (data.databases || [])) console.log(db);
    if (!data.databases || !data.databases.length) console.log('（未枚举到数据库）');
  }
  // --tables / --columns / --dump
  for (const [db, tabs] of Object.entries(data.tables || {})) {
    for (const t of tabs) {
      const key = `${db}.${t}`;
      const cols = data.columns ? data.columns[key] : null;
      const rows = data.rows ? data.rows[key] : null;
      if (Array.isArray(rows) && rows.length) {
        const showCols = cols || Object.keys(rows[0]);
        console.log(`[${key}]  共 ${rows.length} 行`);
        console.log('  ' + showCols.join(' | '));
        for (const row of rows.slice(0, 50)) {
          console.log('  ' + showCols.map(c => row[c] == null ? '' : row[c]).join(' | '));
        }
        if (rows.length > 50) console.log(`  …（仅显示前 50 行，共 ${rows.length} 行）`);
      } else if (cols && cols.length) {
        console.log(`${key}: ${cols.join(', ')}`);
      } else {
        console.log(key);
      }
    }
  }
  // --count
  if (data.counts) {
    for (const [k, v] of Object.entries(data.counts)) console.log(`${k}: ${v == null ? 'N/A' : v} 行`);
  }
  // --search：输出匹配的表名和列名汇总
  if (data.search) {
    console.log(`search keyword: ${data.search.keyword}`);
    if (data.search.matchedTables && data.search.matchedTables.length) {
      console.log(`matched tables: ${data.search.matchedTables.join(', ')}`);
    } else {
      console.log('matched tables: (none)');
    }
    if (data.search.matchedColumns && data.search.matchedColumns.length) {
      for (const m of data.search.matchedColumns) {
        console.log(`  ${m.table}: ${m.columns.join(', ')}`);
      }
    }
  }
  // --schema：输出表结构定义
  if (data.schemas && Object.keys(data.schemas).length) {
    console.log('schemas:');
    for (const [k, v] of Object.entries(data.schemas)) {
      console.log(`  ${k}: ${v == null ? '(null)' : v}`);
    }
  }
}

async function runSingleScan(sm, url, args) {
  const bodyParams = args.body ? JSON.parse(args.body) : {};
  const config = buildConfig(args);
  // [P0-SEC] 目标先过一遍 scope（与 scanRoutes sanitizeStart 同步拦截同构）：越界直接报错，
  // 一个包都不发。直连模式（-d）无 HTTP 请求可言，不参与 scope 判定。
  const scopeRules = args.scope && !args.direct
    ? parseScope(String(args.scope).split(',').map(s => s.trim()).filter(Boolean))
    : null;
  if (scopeRules?.enabled) assertInScope(String(url), scopeRules);
  const auth = buildAuth(args);
  // [本期新增] --test-headers：把显式请求头转为注入点字段。被纳入注入点的头不再经 auth 透传，
  // 否则 httpClient.mergeAuthHeaders 会用原始值覆盖注入 payload（请求仍畸形/无注入）。
  // 注入点的原始值由 buildInjectionRequest 始终从 target.headerParams/cookieParams 注入（含基线请求）。
  const injTarget = buildInjectionTargets(args);
  // 被纳入注入点的「请求头」不再经 auth 透传：mergeAuthHeaders 对普通头是**覆盖**语义，
  // 否则会用原始值覆盖注入 payload（请求仍畸形/无注入）。Cookie 头不在此处删除 ——
  // mergeAuthHeaders 对 cookie 是「追加」语义（existing + '; ' + auth.cookie），保留 auth.cookie
  // 既能让注入点的 uid=<payload> 生效，又能带上独立传入的会话 Cookie（如 --cookie session=abc），避免掉会话。
  if (injTarget.headerParams && auth && auth.headers) {
    for (const k of Object.keys(injTarget.headerParams)) delete auth.headers[k];
    if (auth.headers && Object.keys(auth.headers).length === 0) delete auth.headers;
  }
  // 枚举模式：把 CLI 参数解析为 extractScope 挂到 config（对标 sqlmap --dbs/--tables/...）
  const scope = buildExtractScope(args);
  if (scope) config.extractScope = scope;
  // 直连模式（对标 sqlmap -d）：-d <connectionString> --sql-template 'SELECT * FROM t WHERE id={INJECT}'
  const input = args.direct
    ? {
        mode: 'direct',
        connectionString: args.direct,
        driverType: args.driverType || 'memory',
        sqlTemplate: args.sqlTemplate || 'SELECT * FROM users WHERE id={INJECT}',
        config,
      }
    : { url, method: args.method, bodyParams, config, auth, ...injTarget };
  const scanId = await sm.start(input);
  // [P0-SEC] scope 按 scanId 登记：httpClient 在每一跳（含重定向）前取用，防 302 出圈
  if (scopeRules?.enabled) {
    try { registerScanScope(scanId, scopeRules); } catch { /* 登记失败不阻断扫描（入口已校） */ }
  }

  // 订阅事件 → 控制台进度
  const em = eventBus.create(scanId);
  em.on('event', (evt) => {
    const t = evt.type;
    if (t === 'point_discovered') process.stderr.write(`[发现] ${evt.payload.points?.length ?? 0} 个注入点\n`);
    else if (t === 'point_testing') process.stderr.write(`[检测] ${evt.payload.pointId} · ${evt.payload.technique}\n`);
    else if (t === 'detection_found') process.stderr.write(`[命中] ${evt.payload.technique} @ ${evt.payload.pointId}\n`);
    else if (t === 'scan_completed') process.stderr.write(`[完成] 风险等级 ${evt.payload.riskLevel}\n`);
    else if (t === 'scan_error') process.stderr.write(`[错误] ${evt.payload.message}\n`);
  });

  // 轮询扫描状态直到终态（timeoutMs=0 表示无限等待）
  const deadline = args.timeoutMs > 0 ? Date.now() + args.timeoutMs : 0;
  while (true) {
    const s = sm.scans.get(scanId);
    if (s && ['completed', 'stopped', 'error'].includes(s.status)) break;
    if (deadline > 0 && Date.now() >= deadline) break;
    await new Promise((r) => setTimeout(r, 200));
  }

  const report = sm.getReport(scanId);
  if (scopeRules?.enabled) { try { releaseScanScope(scanId); } catch { /* ignore */ } }
  eventBus.dispose(scanId);
  return report;
}

// 攻击操作（对标 sqlmap --os-cmd / --sql-shell / --file-read / --file-write）：
// 复用引擎 Exploiter 对「首个命中注入点」执行。安全红线与 REST 层一致：
//   ① 服务端 EXPLOIT_ENABLED=1 显式开启（双刃剑默认关闭）
//   ② CLI 需显式声明 --authorized（仅限已授权渗透场景）
// 返回 { ok, ... } 或 null（条件不满足/无注入点时打印原因并返回 null）。
async function runExploit(report, args) {
  if (!report || !report.vulns || !report.vulns.length) {
    console.error('[exploit] 未发现注入点，无法执行利用操作');
    return null;
  }
  if (process.env.EXPLOIT_ENABLED !== '1') {
    console.error('[exploit] 利用操作未启用：需设置环境变量 EXPLOIT_ENABLED=1（安全红线，与 REST 层一致）');
    return null;
  }
  if (!args.authorized) {
    console.error('[exploit] 利用操作需显式声明 --authorized（仅限已授权渗透场景）');
    return null;
  }
  const vuln = report.vulns[0];
  const point = (report.points || []).find(p => p.id === vuln.pointId) || (report.points || [])[0];
  if (!point) {
    console.error('[exploit] 报告缺少注入点信息（point）');
    return null;
  }
  const target = report.target || {};
  const exploiter = new Exploiter();
  const ctx = {
    httpClient,
    config: target.config || {},
    target,
    point,
    dbms: report.dbms || vuln.dbms || null,
  };
  let result;
  if (args.udfInstall) {
    console.error(`[exploit] UDF 全链投递（hex=${args.udfHex || '未指定'}）`);
    result = await exploiter.udfInstall(ctx, { hexPath: args.udfHex });
  } else if (args.osCmd) {
    console.error(`[exploit] 执行系统命令: ${args.osCmd}`);
    result = await exploiter.osShell(ctx, args.osCmd);
  } else if (args.osShell === true) {
    await runShellRepl('os', ctx, exploiter);
    return null;
  } else if (typeof args.osShell === 'string') {
    console.error(`[exploit] 执行系统命令: ${args.osShell}`);
    result = await exploiter.osShell(ctx, args.osShell);
  } else if (args.sqlShell === true) {
    await runShellRepl('sql', ctx, exploiter);
    return null;
  } else if (typeof args.sqlShell === 'string') {
    console.error(`[exploit] 执行 SQL: ${args.sqlShell}`);
    result = await exploiter.sqlShell(ctx, args.sqlShell);
  } else if (args.fileRead) {
    console.error(`[exploit] 读取目标文件: ${args.fileRead}`);
    result = await exploiter.fileRead(ctx, args.fileRead);
  } else if (args.fileWrite) {
    if (!args.fileDest) {
      console.error('[exploit] --file-write 需配合 --file-dest <远程路径>');
      return null;
    }
    console.error(`[exploit] 写入目标文件: ${args.fileDest}`);
    result = await exploiter.fileWrite(ctx, args.fileWrite, args.fileDest);
  }
  console.log(JSON.stringify(result, null, 2));
  return result;
}

// 交互式 shell REPL（对标 sqlmap --sql-shell / --os-shell）：
// readline 循环，逐条执行并打印结果，exit/quit 退出。输出走 stderr 提示、stdout 结果。
/** @param {any} kind @param {object} ctx @param {any} exploiter */
async function runShellRepl(kind, ctx, exploiter) {
  const readline = await import('node:readline/promises');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  console.error(`[${kind}-shell] 交互模式（对标 sqlmap --${kind}-shell）；输入 exit 退出`);
  try {
    for (;;) {
      const line = (await rl.question(`${kind}-shell> `)).trim();
      if (!line) continue;
      if (line === 'exit' || line === 'quit') break;
      const r = kind === 'sql' ? await exploiter.sqlShell(ctx, line) : await exploiter.osShell(ctx, line);
      if (r && r.ok) {
        const out = r.value ?? r.raw ?? (r.status != null ? `status=${r.status}` : '(无回显)');
        console.log(typeof out === 'string' ? out : JSON.stringify(out, null, 2));
        if (r.note) console.error(`[*] ${r.note}`);
      } else {
        console.error(`[!] ${r?.error || '执行失败'}`);
      }
    }
  } finally {
    rl.close();
  }
}

// [对标 sqlmap --identify-waf] 只做 WAF 指纹识别 + 推荐 tamper 链：
//   ① 被动：抓一次基线响应，用响应头/体匹配 62 个 WAF 指纹（零额外发包）
//   ② 主动：发 WAF 触发 payload 观察拦截响应（被动无果时的兜底）
// 全程不发起注入检测，对目标零检出副作用；用于扫描前「先摸清对面是什么 WAF」。
async function runIdentifyWaf(args) {
  const { WafIdentifier } = await import('../src/core/waf/WafIdentifier.js');
  const { recommend } = await import('../src/core/waf/wafRecommend.js');
  const { buildEgressOpts } = await import('../src/engine/egressOpts.js');
  const waf = new WafIdentifier();
  const vendors = new Map();

  // ① 被动识别（基线响应）
  try {
    const res = await httpClient.request(
      buildEgressOpts({}, {
        method: 'GET',
        url: args.url,
        headers: args.headers ? parseHeaders(args.headers) : {},
      })
    );
    const cands = waf.identify({ status: res?.status, headers: res?.headers || {}, body: String(res?.data ?? '') });
    for (const c of cands) {
      if (c && c.vendor) vendors.set(c.vendor, c);
    }
  } catch (e) {
    console.error(`[identify-waf] 基线请求失败：${e.message}`);
  }

  // ② 主动探测（仅在无厂商命中时才有意义，但这里保留：多一路证据不亏）
  try {
    const probe = await waf.activeProbe({ baseUrl: args.url, url: args.url, config: {} }, httpClient);
    if (probe && probe.detected) {
      const v = probe.vendor || 'unknown';
      const prev = vendors.get(v);
      if (!prev || (probe.confidence || 0) > (prev.confidence || 0)) {
        vendors.set(v, { vendor: v, confidence: probe.confidence, evidence: 'active probe' });
      }
    }
  } catch (e) {
    console.error(`[identify-waf] 主动探测失败：${e.message}`);
  }

  const list = [...vendors.values()].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
  if (!list.length) {
    console.log(JSON.stringify({
      target: args.url,
      waf: { detected: false },
      note: '未识别到已知 WAF 指纹：可能是自研/未收录设备，或当前请求未触发拦截（可加 --proxy 或指定路径重试）',
    }, null, 2));
    return;
  }
  const rec = recommend(/** @type {any} */ (list.map((v) => ({ vendor: v.vendor }))));
  console.log(JSON.stringify({
    target: args.url,
    waf: {
      detected: true,
      vendors: list.map((v) => ({ vendor: v.vendor, confidence: v.confidence, evidence: v.evidence || null })),
      best: list[0].vendor,
    },
    recommendedTamper: rec,
  }, null, 2));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  // [goal 批次 A-2] 台账检索子命令：node cli.js ledger list | ledger show <scanId>
  const argvRaw = process.argv.slice(2);
  if (argvRaw[0] === 'ledger') {
    const { listScans, getScan } = await import('../src/services/scanLedger.js');
    const sub = argvRaw[1] || 'list';
    if (sub === 'list') {
      const rows = listScans(Number(argvRaw[2]) || 50);
      if (!rows.length) { console.log('（台账为空）'); process.exit(0); }
      console.log(`共 ${rows.length} 次扫描（新→旧）：`);
      for (const r of rows) {
        console.log(`  ${r.scanId}  ${r.finishedAt || ''}  ${r.target}  vulns=${r.vulns} verdict=${r.verdict || '-'}`);
      }
      process.exit(0);
    }
    if (sub === 'show') {
      const id = argvRaw[2];
      if (!id) { console.error('用法: cli.js ledger show <scanId>'); process.exit(1); }
      const rec = getScan(id);
      if (!rec) { console.error(`台账无此扫描: ${id}`); process.exit(1); }
      console.log(JSON.stringify(rec.meta, null, 2));
      console.log('文件清单:');
      for (const f of rec.files) console.log('  ' + f);
      console.log(`目录: ${rec.dir}`);
      process.exit(0);
    }
    console.error(`未知子命令: ledger ${sub}（支持 list / show）`);
    process.exit(1);
  }
  // 对标 sqlmap -r：请求文件优先于 -u，先应用再校验目标参数
  if (args.requestFile && !applyRequestFile(args)) process.exit(1);
  // 对标 sqlmap -l / -m：日志文件与批量文件同样可替代 -u
  if (args.help || (!args.url && !args.batch && !args.direct && !args.logFile)) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }
  // [P1 2026-09-15] --advise：扫描前风险评估。
  // 刻意放在 checkTor/扫描之前 —— 评估**不发起任何请求**，只看 URL 与参数。
  // 默认打印后退出；加 --yes 才继续（把「人看过建议」变成显式动作）。
  if (args.advise) {
    const { buildAdvice, printAdvice, allowedToContinue } = await import('./cli/advise.js');
    const cfg = buildConfig(args);
    const advice = buildAdvice(args, cfg);
    printAdvice(advice, args);
    if (!allowedToContinue(advice, args)) process.exit(0);
  }
  // 自定义 tamper 文件（--tamper=path/to/custom.js）异步加载注册（buildConfig 消费 tamperResolved）
  if (args.tamper) {
    args.tamperResolved = await resolveTamperPlugins(args.tamper);
  }
  // 对标 sqlmap --check-tor：先验证 Tor 出口（失败退出，不发起任何扫描）
  if (args.checkTor) {
    const proxy = args.tor ? 'socks5://127.0.0.1:9050' : args.proxy;
    if (!proxy) {
      console.error('--check-tor 需要配合 --tor 或 --proxy 使用');
      process.exit(1);
    }
    if (!(await checkTor(proxy))) process.exit(1);
  }

  // [对标 sqlmap --identify-waf] 识别完成即退出，不进入扫描流程
  if (args.identifyWaf) {
    await runIdentifyWaf(args);
    process.exit(0);
  }

  // 枚举参数组合校验（对标 sqlmap 用法约束）
  const enumErr = validateEnumArgs(args);
  if (enumErr) {
    console.error(enumErr);
    process.exit(1);
  }
  const enumActive = isEnumMode(args);

  // ---- 批量模式 ----
  if (args.batch) {
    const urls = readUrlList(args.batch);
    // [P1-2] 全局限速：每个扫描实例的 ratePerSec = 总速率 / 并发数
    // 确保多个并发扫描的总速率 ≤ ratePerSec，防止打爆目标
    const perScanRate = Math.max(1, Math.ceil(args.ratePerSec / args.concurrency));
    console.error(`批量扫描 ${urls.length} 个目标，并发 ${args.concurrency}，每扫描限速 ${perScanRate} req/s（总 ≤ ${args.ratePerSec} req/s）`);
    const results = [];
    // [P1-2] 共享 HttpClient：批量模式所有 ScanManager 共用同一个 httpClient 单例
    // → 所有 scanId 的令牌桶都在同一个 buckets Map 中，forScan 时共享底层的串行化 Promise 链
    // 均分方案 + 共享 HttpClient = 总速率严格 ≤ ratePerSec
    // （原实现每 URL new ScanManager 但 ScanManager 构造器已用模块级 httpClient 单例，
    //  实际已共享；此注释确认此行为是正确设计而非巧合）
    // 并发池：按 args.concurrency 限制并发数
    const pool = async (items, worker, concurrency) => {
      const queue = items.slice();
      let cursor = 0;
      const next = async () => {
        while (cursor < queue.length) {
          const item = queue[cursor++];
          await worker(item);
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, () => next()));
    };
    await pool(urls, async (url) => {
      const sm = new ScanManager();
      // 用均分后的速率替换原始 ratePerSec
      const scanArgs = { ...args, ratePerSec: perScanRate };
      const report = await runSingleScan(sm, url, scanArgs);
      results.push({ url, report, riskLevel: report?.riskLevel || 'error', vulns: report?.vulns?.length || 0 });
      console.error(`[${results.length}/${urls.length}] ${url} → ${report?.riskLevel || '失败'}`);
    }, args.concurrency);

    // 聚合摘要
    const byRisk = {};
    for (const r of results) { byRisk[r.riskLevel] = (byRisk[r.riskLevel] || 0) + 1; }
    console.error(`\n批量扫描完成：${results.length} 个目标`);
    console.error(`  风险分布: ${Object.entries(byRisk).map(([k, v]) => `${k}=${v}`).join(' ')}`);

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt;
      for (const r of results) {
        if (r.report) {
          const safeName = r.url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
          writeFileSync(join(args.out, `${safeName}.${ext}`), formatReport(r.report, fmt), 'utf-8');
          // [goal 批次 A-2] 扫描台账：每次扫描自动登记可追溯快照（meta/report/poc）
          // [FIX 2026-09-18] PoC 落盘此前恒为空：ReportGenerator 的 poc 是**惰性且不可变**挂载
          // （_attachPoc 返回新对象、不回写入参），而此处把【原始】r.report 交给 recordScan，
          // 其 `if (!v.poc) continue` 于是全部命中 → poc/ 目录恒空。实测 163 次真实台账
          // 0 个 poc 文件。改传 attachPoc 的导出形态（公开方法，与渲染同源）。
          try {
            const rgLedger = new ReportGenerator();
            scanLedger.recordScan(rgLedger.attachPoc(r.report), {
              html: rgLedger.toHTML(r.report),
              markdown: rgLedger.toMarkdown(r.report),
            });
          } catch (e) { console.error(`台账登记失败: ${e.message}`); }
        }
      }
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: r.url, riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }

    const hasHigh = results.some(r => r.riskLevel === 'Critical' || r.riskLevel === 'High');
    process.exit(hasHigh ? 2 : 0);
  }

  // ---- 日志文件批量模式（对标 sqlmap -l） ----
  if (args.logFile) {
    const requests = parseLogFile(args.logFile);
    if (requests.length === 0) {
      console.error('日志文件未解析出任何请求（支持 Burp XML 导出或纯文本多请求日志）');
      process.exit(1);
    }
    const perScanRate = Math.max(1, Math.ceil(args.ratePerSec / args.concurrency));
    console.error(`日志批量 ${requests.length} 个请求，并发 ${args.concurrency}，每扫描限速 ${perScanRate} req/s（总 ≤ ${args.ratePerSec} req/s）`);
    const results = [];
    const pool = async (items, worker, concurrency) => {
      const queue = items.slice();
      let cursor = 0;
      const next = async () => {
        while (cursor < queue.length) {
          const item = queue[cursor++];
          await worker(item);
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, () => next()));
    };
    await pool(requests, async (req) => {
      const sm = new ScanManager();
      // 每请求从 args 派生扫描参数：覆盖 url/method/body/headers/cookie（复用 -r 的字段映射逻辑）
      const scanArgs = { ...args, ratePerSec: perScanRate };
      scanArgs.url = req.url;
      scanArgs.method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? req.method : 'GET';
      if (req.body) {
        const bodyJson = bodyToJsonString(req.body);
        if (bodyJson) scanArgs.body = bodyJson;
      }
      const cookieKey = Object.keys(req.headers).find(k => k.toLowerCase() === 'cookie');
      if (cookieKey) scanArgs.cookie = req.headers[cookieKey];
      const other = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const kl = k.toLowerCase();
        if (kl === 'cookie' || kl === 'host' || kl === 'content-length') continue;
        other[k] = v;
      }
      if (Object.keys(other).length) scanArgs.headerObj = other;
      const report = await runSingleScan(sm, req.url, scanArgs);
      results.push({ url: req.url, report, riskLevel: report?.riskLevel || 'error', vulns: report?.vulns?.length || 0 });
      console.error(`[${results.length}/${requests.length}] ${req.url} → ${report?.riskLevel || '失败'}`);
    }, args.concurrency);

    const byRisk = {};
    for (const r of results) { byRisk[r.riskLevel] = (byRisk[r.riskLevel] || 0) + 1; }
    console.error(`\n日志批量扫描完成：${results.length} 个请求`);
    console.error(`  风险分布: ${Object.entries(byRisk).map(([k, v]) => `${k}=${v}`).join(' ')}`);

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt;
      for (const r of results) {
        if (r.report) {
          const safeName = r.url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
          writeFileSync(join(args.out, `${safeName}.${ext}`), formatReport(r.report, fmt), 'utf-8');
        }
      }
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: r.url, riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }
    const hasHigh = results.some(r => r.riskLevel === 'Critical' || r.riskLevel === 'High');
    process.exit(hasHigh ? 2 : 0);
  }

  // ---- 单目标模式（HTTP 或直连） ----
  const sm = new ScanManager();
  const report = await runSingleScan(sm, args.direct || args.url, args);
  if (!report) {
    console.error('扫描超时或报告不存在');
    process.exit(1);
  }

  const jsonContent = JSON.stringify(report, null, 2);
  const exploitMode = !!(args.osCmd || args.sqlShell || args.fileRead || args.fileWrite);
  if (args.out) {
    const { writeFileSync } = await import('node:fs');
    // [P1-FIX 2026-09-05] 按 --format 分发导出（json|csv|markdown|html），与 REST /report/export 同源
    const fmt = String(args.format || 'json').toLowerCase();
    // [goal 批次 A-3] -o 目录语义：路径是已存在目录或以分隔符结尾 → 写 report.<ext> 组
    //（sqlmap 风格），否则保持单文件兼容。交付默认 --format html 时同时落 md 便于交接。
    const outIsDir = (() => { try { return require('node:fs').statSync(args.out).isDirectory(); } catch { return /[\\/]$/.test(args.out); } })();
    if (outIsDir) {
      const { mkdirSync } = await import('node:fs');
      const { join: pj } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      writeFileSync(pj(args.out, `report.${fmt === 'markdown' || fmt === 'md' ? 'md' : fmt}`), formatReport(report, fmt), 'utf-8');
      if (fmt === 'html') writeFileSync(pj(args.out, 'report.md'), formatReport(report, 'markdown'), 'utf-8');
      if (fmt === 'markdown' || fmt === 'md') writeFileSync(pj(args.out, 'report.html'), formatReport(report, 'html'), 'utf-8');
    } else {
      writeFileSync(args.out, formatReport(report, fmt), 'utf-8');
    }
    // [goal 批次 A-2] 扫描台账：单 URL 模式自动登记可追溯快照（meta/report/poc）
    // [FIX 2026-09-18] 同批量模式：必须传 attachPoc 的导出形态，否则 poc/ 恒为空
    // （_attachPoc 不可变返回新对象，原始 report 上永远没有 v.poc）。
    try {
      const rgLedger = new ReportGenerator();
      scanLedger.recordScan(rgLedger.attachPoc(report), {
        html: rgLedger.toHTML(report),
        markdown: rgLedger.toMarkdown(report),
      });
    } catch (e) { console.error(`台账登记失败: ${e.message}`); }
    console.error(`报告已写入 ${args.out}（格式 ${fmt}）`);
  } else if (enumActive || args.dump) {
    // 枚举/拖库模式：默认打印 report.data 精简视图（文本，对标 sqlmap 终端输出）
    printExtractView(report);
  } else if (!exploitMode) {
    console.log(jsonContent);
  }

  // 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）：
  // 需 EXPLOIT_ENABLED=1 + --authorized；对首个命中注入点执行并打印结果
  if (exploitMode) {
    await runExploit(report, args);
    const risk = report.riskLevel;
    process.exit(risk === 'Critical' || risk === 'High' ? 2 : 0);
  }

  const risk = report.riskLevel;
  process.exit(risk === 'Critical' || risk === 'High' ? 2 : 0);
}

// 仅在直接以脚本运行时启动 main（import 进测试时不触发）
import { pathToFileURL } from 'node:url';
const invokedDirectly = (() => {
  try {
    return process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main().catch((e) => {
    logger.error(`CLI 执行失败：${e.message}`);
    console.error(e.message);
    process.exit(1);
  });
}

// 导出供单测使用（仍在 cli.js 定义的符号；args 族的再导出见文件顶部）
export { buildConfig, buildExtractScope, validateEnumArgs, printExtractView, runSingleScan, buildInjectionTargets };

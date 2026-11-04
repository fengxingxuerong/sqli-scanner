#!/usr/bin/env node
// CLI 模式（P1-U5）：无 UI 的命令行扫描入口，复用同一 ScanManager。
// 用法：
//   单目标：node bin/cli.js -u <url> [--method GET|POST] [--body '{"k":"v"}'] [--format json|html|csv|markdown]
//   XML/SOAP：node bin/cli.js -u <url> --method POST --xml-body-file envelope.xml
//   直连：  node bin/cli.js -d "sqlite://test.db" --sql-template "SELECT * FROM t WHERE id={INJECT}"
//   批量：  node bin/cli.js -m <urls.txt> [--format json] [--concurrency 2]
// 事件经 eventBus 订阅转控制台进度输出，扫描结束打印报告到 stdout 并可按 --format 导出到文件。
import { ScanManager } from '../src/engine/ScanManager.js';
import * as eventBus from '../src/core/eventBus.js';
import { logger } from '../src/core/logger.js';
// 终端控制序列消毒（拖库结果与 os-shell 回显都是目标可控字节流）
import { sanitizeForTerminal } from '../src/core/terminalSafe.js';
// 对标 sqlmap -r：解析 Burp/curl 文本请求文件（parseRequestFile 在 args.js 消费）
// 攻击操作（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write）：复用引擎 Exploiter
import { Exploiter } from '../src/engine/Exploiter.js';
import { httpClient } from '../src/core/httpClient.js';
// [D240 对标 sqlmap -t] 原始流量落盘（旁路；扫描主流程可选启用）
import { enableTrafficLog } from '../src/core/http/trafficLog.js';
// [P1-FIX 2026-09-05] --format 出口：原为死参数（解析后从未消费，-o 恒写 JSON）。
// ReportGenerator 的 toCSV/toMarkdown/toHTML 与 REST /report/export 同源，直接复用。
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { renderScanSummaryPanel, batchHitLines, batchNextLine, batchWriteHint, printBatchHitsAndNext, printBatchSummary, urlOfLogRequest } from './cli/summaryPanel.js';
import { readFileSync } from 'node:fs';
import * as scanLedger from '../src/services/scanLedger.js';
// [D198] --cleanup：撤销配方读自写副作用台账，执行走 exploit 同门同上下文
import { cleanupChannel, cleanupSideEffects, readSideEffects } from '../src/services/sideEffectLedger.js';
// [P1-1 收口 2026-09-29] 利用能力开关的**唯一判据**（与 REST 的 /exploit/*、
// /exploit/capabilities、sqlmap 桥的 --os-shell 门控同源）。
import { isExploitEnabled } from '../src/core/exploitFlag.js';
// [P0-SEC 2026-09-09] --scope 接线：CLI 直走 ScanManager 不经 scanRoutes，需在本层完成
// 「目标先校验 + 按 scanId 登记」，否则 --scope 是静默 no-op（httpClient 逐跳取用登记项）。
import { parseScope, assertInScope, assertDirectDbInScope, registerScanScope, releaseScanScope } from '../src/core/scopeGuard.js';
import { printHelp, printVersion } from './cli/help.js';
// [D197] --list-tampers 的渲染层（对标 sqlmap --list-tampers）：入口元信息查询，与 --version 同形态
import { printTamperCatalog } from './cli/tamperCatalog.js';
import { parseXmlBody, xmlLeafPaths } from '../src/core/xmlBody.js';
// [D24 2026-10-09 扩展生态] 自定义检测条目：validate（纯校验）+ merge（冲突拒绝）+ ALS 注入
import { validateCustomEntries, mergeCustomEntries } from '../src/engine/payloads/customPayloads.js';
import { PAYLOAD_REGISTRY, runWithCustomPayloads } from '../src/engine/payloadRegistry.js';
import {
  parseArgs,
  parseLogFile,
  resolveTamperPlugins,
  parseHeaders,
  bodyToJsonString,
  applyRequestFile,
  buildAuth,
  checkTor,
  unknownFlagError,
} from './cli/args.js';
// [D238] 报告输出函数族：测试从 bin/cli.js 导入的三个符号按 args re-export 同款先例保持路径不变
export { formatReport, printExtractView, writeFixPromptsForReport } from './cli/reportOutput.js';
import {
  buildInjectionTargets,
  buildConfig,
  isEnumMode,
  buildExtractScope,
  validateEnumArgs,
  resolveBodyChannel,
  declaredContentType,
} from './cli/config.js';
// [D238] 报告输出/落盘函数族已抽至 cli/reportOutput.js（纯搬移，函数体逐字未动）
import { formatReport, applyReproCheck, emitSingleScanOutput } from './cli/reportOutput.js';
// [D101 2026-10-18] 注入点 × auth 同名夹击去重（与 REST sanitizeStart 共用同一实现）
import { dropInjectionOverlapFromAuth } from '../src/core/authInjectionOverlap.js';
// [D41 2026-10-11] 配置档案（对标 sqlmap -c/--save）：--config 预载 + --save-config 增量落盘
import { presetFromArgv, saveConfigFile } from './cli/configFile.js';
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
  unknownFlagError,
} from './cli/args.js';

// --format 分发（json|csv|markdown|md|html|sarif|db-json）：单目标 -o 与批量目录导出共用。
/**
 * [D195] 扫描进度事件 → 控制台行。独立成函数：runSingleScanInner 圈复杂度基线内。
 * point_discovered 事件自带完整点位（param/location），存索引供 [检测]/[命中] 行渲染
 * 人读标注（此前只有 pointId 哈希，用户看不出在测哪个参数）；引擎 point_testing
 * payload 也带 param/location（预选点位跳过 discovery 时有）。
 * @returns {(evt: object) => void}
 */
function makeScanProgressLogger() {
  const pointIndex = new Map();
  const pointLabel = (pointId) => {
    const p = pointIndex.get(pointId);
    return p ? `${p.param}@${p.location || p.in || '?'}` : pointId;
  };
  return (evt) => {
    const t = evt.type;
    if (t === 'point_discovered') {
      for (const p of evt.payload.points || []) pointIndex.set(p.id, p);
      process.stderr.write(`[发现] ${evt.payload.points?.length ?? 0} 个注入点\n`);
    } else if (t === 'point_testing') {
      if (evt.payload.param) pointIndex.set(evt.payload.pointId, evt.payload);
      process.stderr.write(`[检测] ${pointLabel(evt.payload.pointId)} · ${evt.payload.technique}\n`);
    } else if (t === 'detection_found') process.stderr.write(`[命中] ${evt.payload.technique} @ ${pointLabel(evt.payload.pointId)}\n`);
    else if (t === 'scan_completed') process.stderr.write(`[完成] 风险等级 ${evt.payload.riskLevel}\n`);
    else if (t === 'scan_error') process.stderr.write(`[错误] ${evt.payload.message}\n`);
  };
}

// [D195] 人读结果面板拆至 cli/summaryPanel.js（pre-commit 体积门禁）；re-export 供测试
export { renderScanSummaryPanel, batchHitLines, batchNextLine, batchWriteHint, printBatchHitsAndNext };

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

// [D24 2026-10-09] 外层只负责把自定义条目挂进本次扫描的异步上下文；不传 --payload-file 时
// 直接走 Inner，与旧调用路径逐位相同（无 ALS 开销、无行为差异）。
async function runSingleScan(sm, url, args) {
  const custom = Array.isArray(args.payloadEntries) && args.payloadEntries.length > 0
    ? args.payloadEntries
    : null;
  if (custom) return runWithCustomPayloads(custom, () => runSingleScanInner(sm, url, args));
  return runSingleScanInner(sm, url, args);
}

/** [D155] body 走 JSON 语义的播报理由：声明 CT 优先（json 字样），其次嵌套检测。纯函数。 */
function jsonChannelWhy(declaredCt) {
  return /json/i.test(declaredCt)
    ? `声明的 Content-Type 是 ${declaredCt.split(';')[0]}`
    : '检测到嵌套 JSON';
}

/**
 * [D159 拆分] HTTP 目标 input 组装（原内联在 runSingleScanInner；加 fileParts 后超复杂度基线）。
 * @param {string} url
 * @param {any} args
 * @param {{bodyParams:any, jsonBody:any, xmlBody:any, config:any, auth:any, injTarget:any}} parts
 * @returns {any}
 */
function buildHttpScanInput(url, args, parts) {
  const { bodyParams, jsonBody, xmlBody, config, auth, injTarget } = parts;
  return {
    url,
    method: args.method,
    bodyParams,
    jsonBody,
    xmlBody,
    // [D159] multipart 文件字段（-r 抓包）：TargetParser 建 filename 注入点，
    // injection.js 重建报文时保留文件字段结构
    fileParts: Array.isArray(args.fileParts) ? args.fileParts : [],
    config,
    auth,
    ...injTarget,
  };
}

async function runSingleScanInner(sm, url, args) {
  const parsedBody = args.body ? JSON.parse(args.body) : {};
  // [JSON-BODY-FIX 2026-09-20] 判定本体在 cli/config.js 的 resolveBodyChannel（带完整理由注释）：
  // 含嵌套的 --body 走 jsonBody（引擎 _discoverJsonLeaves 取叶子路径），扁平 body 继续
  // bodyParams（urlencoded），既有行为不变。这里只负责接线与播报。
  // [D155] 第二个入参 = 调用方**声明**的 Content-Type：声明了 application/json 时，扁平
  // JSON 也走 jsonBody —— 否则只吃 JSON 的目标收到 urlencoded（415/400），注入值从未进业务逻辑。
  // （[跨会话类型补丁 2026-10-25] why 构造抽到 jsonChannelWhy —— runSingleScanInner 复杂度/行数
  //   只许持平变浅；行为零变化，由 cli.jsonBody.test.js 9 例背书。）
  const declaredCt = declaredContentType(args);
  const { bodyParams, jsonBody } = resolveBodyChannel(parsedBody, declaredCt);
  if (jsonBody) {
    console.log(`  [body] ${jsonChannelWhy(declaredCt)} → 按 application/json 语义扫描，注入点取自叶子路径（如 user.id / tags.0）；未声明 JSON 的扁平 body 仍走 urlencoded。`);
  }
  // [2026-10-01] XML / SOAP body 通道（对标 ghauri XML·SOAP）：--xml-body 直接给原文，
  // --xml-body-file 读文件（多行 SOAP 信封）。解析失败的原文**照样往下传** —— 由引擎按
  // 「认不出即放弃」的保守口径处理，CLI 只负责如实提示（静默丢弃 = 用户以为在测 XML）。
  let xmlBody = null;
  if (typeof args.xmlBody === 'string' && args.xmlBody) xmlBody = args.xmlBody;
  else if (typeof args.xmlBodyFile === 'string' && args.xmlBodyFile) {
    try {
      xmlBody = readFileSync(args.xmlBodyFile, 'utf8');
    } catch (e) {
      console.error(`  [xml-body] 文件不可读：${args.xmlBodyFile}（${e?.message || e}）`);
      process.exitCode = 2;
      return;
    }
  }
  if (xmlBody) {
    const probe = parseXmlBody(xmlBody);
    if (probe.ok) {
      const paths = xmlLeafPaths(probe.tree);
      console.log(`  [xml-body] 解析成功，叶子注入点 ${paths.length} 个：${paths.slice(0, 5).join(', ')}${paths.length > 5 ? ' …' : ''}`);
    } else {
      console.warn(`  [xml-body] 解析失败（${probe.reason}）：本通道只支持「元素+文本」形态，`
        + '注释/CDATA/DOCTYPE/处理指令一律不支持 —— 该 body 不会产生注入点。');
    }
  }
  const config = buildConfig(args);
  // [P0-SEC] 目标先过一遍 scope：越界直接报错，一个包都不发。
  //   HTTP 目标校 URL；**直连（-d）校数据库主机** —— 原先这里写 `&& !args.direct`
  //   并注释称"直连不参与 scope 判定 / 与 scanRoutes 同构"，但 REST 侧自 2026-09-25 起
  //   是按 DB 主机校的 ⇒ 同构那句成了假话，实际效果是同一个 `-d` 从 REST 进要过红线、
  //   从 CLI 进完全不过。两条入口现在共用 core/scopeGuard.assertDirectDbInScope。
  const scopeRules = args.scope
    ? parseScope(String(args.scope).split(',').map((s) => s.trim()).filter(Boolean))
    : null;
  if (scopeRules?.enabled) {
    if (args.direct) {
      // 不传 driverType 的默认值（memory）当"内嵌"放行 = 红线白设，故这里只认操作者显式声明的
      assertDirectDbInScope({ connectionString: String(args.direct), driverType: args.driverType }, scopeRules);
    } else {
      assertInScope(String(url), scopeRules);
    }
  }
  /** @type {any} */ let auth = buildAuth(args);
  // [D101 2026-10-18] 去重口径收敛为共享单点实现（core/authInjectionOverlap.js，与 REST
  // sanitizeStart 同源）：① 非 cookie 注入点头从 auth.headers 删同名副本（**大小写不敏感**
  // ——原实现在此精确键名 delete，请求文件与 --header 混用产生大小写变体时会漏删 ⇒
  // mergeAuthHeaders 覆盖语义把注入值顶回原值）；② --cookie 已升为 cookie 注入点的键从
  // auth.cookie 除去同名对，残余会话键重拼（原 leftover 逻辑等价迁移，P0-FIX 2026-09-18 语义
  // 不变：同名双份 `uid=<payload>; uid=1` 的生效顺序取决于目标解析，必须避免）。
  // 不删 auth.headers.cookie（会话语义）与 authorization（CLI 侧本就在 buildInjectionTargets
  // 的 EXCLUDE 里，不作注入头）。
  const injTarget = buildInjectionTargets(args);
  auth = dropInjectionOverlapFromAuth(auth, {
    headerParams: injTarget.headerParams,
    cookieParams: injTarget.cookieParams,
  });
  // 枚举模式：把 CLI 参数解析为 extractScope 挂到 config（对标 sqlmap --dbs/--tables/...）
  const scope = buildExtractScope(args);
  if (scope) config.extractScope = scope;
  // 直连模式（对标 sqlmap -d）：-d <connectionString> --sql-template 'SELECT * FROM t WHERE id={INJECT}'
  // [D187] driverType 不再默认 'memory'：未传 --driver 时由 createTarget 按 DSN scheme 推断
  //（此前 mysql:// DSN 会静默走内存自检驱动，报告出假命中）。
  const input = args.direct
    ? {
        mode: 'direct',
        connectionString: args.direct,
        driverType: args.driverType || undefined,
        sqlTemplate: args.sqlTemplate || 'SELECT * FROM users WHERE id={INJECT}',
        config,
      }
    : buildHttpScanInput(url, args, { bodyParams, jsonBody, xmlBody, config, auth, injTarget });
  const scanId = await sm.start(input);
  // [P0-SEC] scope 按 scanId 登记：httpClient 在每一跳（含重定向）前取用，防 302 出圈
  // 只给 HTTP 扫描登记：直连不发 HTTP 请求，逐跳校验没有对象可校（入口已按 DB 主机校过）
  if (scopeRules?.enabled && !args.direct) {
    try { registerScanScope(scanId, scopeRules); } catch { /* 登记失败不阻断扫描（入口已校） */ }
  }

  // 订阅事件 → 控制台进度
  const em = eventBus.create(scanId);
  em.on('event', makeScanProgressLogger());

  // 轮询扫描状态直到终态（timeoutMs=0 表示无限等待）
  const deadline = args.timeoutMs > 0 ? Date.now() + args.timeoutMs : 0;
  while (true) {
    const s = sm.scans.get(scanId);
    if (s && ['completed', 'stopped', 'error'].includes(s.status)) break;
    if (deadline > 0 && Date.now() >= deadline) break;
    await new Promise((r) => setTimeout(r, 200));
  }

  // [P1-PERF 2026-11-02] 终态报告默认是冻结快照；CLI 后续要写 repro/输出，显式取可写克隆。
  const report = sm.getReport(scanId, { mutable: true });
  if (scopeRules?.enabled) { try { releaseScanScope(scanId); } catch { /* ignore */ } }
  eventBus.dispose(scanId);
  return report;
}

// 攻击操作（对标 sqlmap --os-cmd / --sql-shell / --file-read / --file-write）：
// 复用引擎 Exploiter 对「首个命中注入点」执行。安全红线与 REST 层一致：
//   ① 服务端 EXPLOIT_ENABLED 显式开启（双刃剑默认关闭）
//   ② CLI 需显式声明 --authorized（仅限已授权渗透场景）
// 返回 { ok, ... } 或 null（条件不满足/无注入点时打印原因并返回 null）。
//
// ⚠️ [P1-1 收口 2026-09-29] 判据**必须**走 core/exploitFlag.isExploitEnabled()。
// 本函数曾写 `process.env.EXPLOIT_ENABLED !== '1'` —— 只认 `1`，于是
// `EXPLOIT_ENABLED=true`（REST 侧允许、.env.example 之外最自然的写法）在这里被拒，
// 出现「同一台机器上 REST 能用、CLI 说没启用」的分歧。判据的取值语义（trim/lowercase、
// 认 1 与 true）只有一处定义，见 core/exploitFlag.js 的头注释。
// 导出供测试直接验证三入口一致性（本函数原为模块私有，测试只能用"读源码正则"这种
// 弱判据；导出后可以直接调它，判据从"文本像不像"升级为"行为对不对"）。
//
// [D200 2026-11-04 拆分] 复杂度基线 GRACE=0，runExploit（61 行存量债）一行不能长；
// 注册表面（--reg-*）接线按「门/上下文」与「动作链」拆开：门与上下文留在
// runExploitCore（旧 runExploit 逐字搬移，只减不增合法瘦身），两条动作链各自成函数 ——
// 旧链在 dispatchExploitAction 一字未改，注册表面在 dispatchRegistryAction（新建）。
const REPL_HANDLED = Symbol('exploit-repl'); // 交互 REPL 已自行输出，runExploitCore 不再打印结果 JSON

export async function runExploit(report, args) {
  return runExploitCore(report, args, dispatchExploitAction);
}

// [D200] 注册表面入口（对标 sqlmap --reg-read/--reg-add/--reg-del）：与 runExploit 同门同上下文。
export async function runExploitRegistry(report, args) {
  return runExploitCore(report, args, dispatchRegistryAction);
}

// main() 是复杂度基线存量函数（273 行），行数与复杂度都不许涨 —— 利用面判定收进模块级助手，
// main 里只留一行调用（替换原 || 链，复杂度净下降）。
const EXPLOIT_OP_KEYS = ['osCmd', 'sqlShell', 'fileRead', 'fileWrite', 'regRead', 'regAdd', 'regDel'];
/** @param {any} args @returns {boolean} 是否请求了任一利用动作 */
function isExploitMode(args) {
  return EXPLOIT_OP_KEYS.some((k) => !!args[k]);
}
// [D198] 扫描后动作面 = 利用动作 + --cleanup（清理是对目标的又一次写/命令执行，同门）
/** @param {any} args @returns {boolean} */
function isPostScanMode(args) {
  return isExploitMode(args) || !!args.cleanup;
}
/** @param {any} args @returns {boolean} 是否请求了注册表操作（走 runExploitRegistry 分支） */
function isRegistryOp(args) {
  return !!(args.regRead || args.regAdd || args.regDel);
}

/** @param {any} report @param {any} args @param {(exploiter:any, ctx:object, args:any)=>Promise<any>} dispatch */
async function runExploitCore(report, args, dispatch) {
  if (!report || !report.vulns || !report.vulns.length) {
    console.error('[exploit] 未发现注入点，无法执行利用操作');
    return null;
  }
  if (!isExploitEnabled()) {
    console.error('[exploit] 利用操作未启用：需设置 EXPLOIT_ENABLED=1（或 true）（安全红线，与 REST 层同一判据）');
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
    // [D198] scanId 透传：file-write / udf / reg-write 的写前登记（sideEffectLedger）依赖它
    // （缺省为 undefined，登记侧按 falsy 跳过 —— 不在这里加 `|| null`，会多一个分支）
    scanId: report.scanId,
  };
  const result = await dispatch(exploiter, ctx, args);
  if (result === REPL_HANDLED) return null;
  console.log(JSON.stringify(result, null, 2));
  return result;
}

/** @param {any} exploiter @param {object} ctx @param {any} args */
async function dispatchExploitAction(exploiter, ctx, args) {
  let result;
  if (args.udfInstall) {
    console.error(`[exploit] UDF 全链投递（hex=${args.udfHex || '未指定'}）`);
    // [D202] --os 显式覆盖 UDF 平台（默认 linux 由 udfInstall 自己决定，传 undefined 不覆盖）
    result = await exploiter.udfInstall(ctx, { hexPath: args.udfHex, platform: ctx.config?.os || args.os });
  } else if (args.osCmd) {
    console.error(`[exploit] 执行系统命令: ${args.osCmd}`);
    result = await exploiter.osShell(ctx, args.osCmd);
  } else if (args.osShell === true) {
    await runShellRepl('os', ctx, exploiter);
    return REPL_HANDLED;
  } else if (typeof args.osShell === 'string') {
    console.error(`[exploit] 执行系统命令: ${args.osShell}`);
    result = await exploiter.osShell(ctx, args.osShell);
  } else if (args.sqlShell === true) {
    await runShellRepl('sql', ctx, exploiter);
    return REPL_HANDLED;
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
  return result;
}

// —— [D200] 注册表参数面归一化（对标 sqlmap --reg-*）——
// 值型旗标（--reg-key/--reg-value/--reg-data/--reg-type）走 OPTIONAL_VALUE_FLAGS 表：
// 带值=字符串；忘给值会落成 true（布尔），这里统一按「非字符串 = 没给」处理并明确报错。
/** @param {string|null} v @returns {string|null} */
function strArg(v) {
  return typeof v === 'string' && v ? v : null;
}

/**
 * @param {any} args
 * @returns {{ error: string, op: null } | { error: null, op: string, key: string, value: string | null, data: string | null, type: string, label: string }}
 */
function normalizeRegistryArgs(args) {
  const on = [args.regRead, args.regAdd, args.regDel].filter(Boolean);
  if (on.length !== 1) {
    return {
      error: on.length === 0
        ? '未指定注册表操作：--reg-read / --reg-add / --reg-del 三选一'
        : '注册表操作一次只执行一种（--reg-read / --reg-add / --reg-del）',
      op: null,
    };
  }
  const op = args.regRead ? 'read' : args.regAdd ? 'add' : 'del';
  const shorthand = strArg(on[0]); // 操作旗标带值 = 键路径速记（对标 sqlmap --reg-read [key]）
  const key = strArg(args.regKey) || shorthand;
  const value = strArg(args.regValue);
  const data = strArg(args.regData);
  const type = strArg(args.regType) || 'REG_SZ';
  if (!key) return { error: '缺少注册表键路径：用 --reg-key <路径>，或操作旗标带值速记（如 --reg-read <路径>）', op: null };
  if (op === 'add' && (!value || !data)) return { error: '--reg-add 需 --reg-value <值名> 与 --reg-data <数据>', op: null };
  if (op === 'del' && !value) return { error: '--reg-del 需 --reg-value <值名>（xp_regdelete 按值名删除）', op: null };
  const label = { read: '读取注册表', add: '写入注册表', del: '删除注册表值' }[op];
  return { error: null, op, key, value, data, type, label };
}

/** @param {any} exploiter @param {object} ctx @param {any} args */
async function dispatchRegistryAction(exploiter, ctx, args) {
  const p = normalizeRegistryArgs(args);
  if (p.error !== null) {
    console.error(`[exploit] ${p.error}`);
    return null;
  }
  console.error(`[exploit] ${p.label}: ${p.key}${p.value ? ` \\ ${p.value}` : ''}`);
  if (p.op === 'read') return exploiter.registryRead(ctx, { key: p.key, value: p.value });
  if (p.op === 'add') return exploiter.registryWrite(ctx, { key: p.key, value: p.value, data: p.data, type: p.type });
  return exploiter.registryDelete(ctx, { key: p.key, value: p.value });
}

// —— [D198] 扫描后动作与利用后清理（对标 sqlmap --cleanup）——
// 撤销配方来自写副作用台账（file_write / udf_install / reg_write 均已写前登记），
// 按 kind 路由通道：SQL 类（DROP FUNCTION / 反向 DML）走 sql-shell，文件/注册表走 os-shell。
// 门与上下文复用 runExploitCore（EXPLOIT_ENABLED + --authorized + 注入点）——清理是对目标的
// 又一次写/命令执行，与 REST /api/exploit/side-effects/cleanup 同门，绝不绕过。
/**
 * @param {any} exploiter @param {object} ctx
 * @returns {(cmd: string, item: object) => Promise<{ok: boolean, output: string, error: string}>}
 */
function makeCleanupExecutor(exploiter, ctx) {
  return async (cmd, item) => {
    const r = cleanupChannel(item && item.kind) === 'sql'
      ? await exploiter.sqlShell(ctx, cmd)
      : await exploiter.osShell(ctx, cmd);
    return {
      ok: !!(r && r.ok),
      output: r && r.value != null ? String(r.value) : (r && r.raw != null ? String(r.raw) : ''),
      error: r && r.error ? String(r.error) : '',
    };
  };
}

/** @param {any} exploiter @param {object} ctx */
async function dispatchCleanup(exploiter, ctx) {
  const scanId = ctx.scanId;
  if (!scanId) return { ok: false, error: '报告缺少 scanId，无法定位写副作用台账' };
  const store = readSideEffects(scanId);
  if (!store.effects.length) {
    return { ok: true, scanId, note: '无已登记的写副作用，无需清理（os-shell/sql-shell 交互不产生可自动撤销的登记项）' };
  }
  const r = await cleanupSideEffects(scanId, makeCleanupExecutor(exploiter, ctx));
  return { ok: r.summary.失败 === 0, scanId, summary: r.summary, results: r.results };
}

/** @param {any} report @param {any} args @returns {Promise<any>} 最后一个动作的结果（利用结果或清理结果） */
async function runPostScanActions(report, args) {
  let out;
  if (isExploitMode(args)) {
    out = await (isRegistryOp(args) ? runExploitRegistry(report, args) : runExploit(report, args));
  }
  if (args.cleanup) out = await runExploitCore(report, args, dispatchCleanup);
  return out;
}
// 导出供测试（cli.cleanup.test.js 验证登记/路由/门，零网络）
export { runPostScanActions };

// —— [D198 对标 sqlmap --purge] 本地痕迹清理（P3，无需 -u / 不发包）——
// 范围＝扫描器**自己的状态**：本地台账根目录（扫描快照 report.json/html/md + poc/、
// 写副作用 side-effects.json、auth.jsonl 审计）与引擎日志。
// **导出目录 reports/ 与用户指定的 --session-file 不碰**（前者是交付物，后者是用户路径）。
// 需显式确认：交互 TTY 走确认提示；非交互必须 --yes（不可静默删审计与快照）。
// @param {string[]} argv
// @param {{targets?: Array<{label: string, path: string, dir?: boolean}>}} [inject]
//        targets 注入缝：测试传自己的临时目录，避免测试删掉真实引擎日志（Windows 上文件被
//        占用时 rmSync 会 EPERM，真实运行时日志目标按 best-effort 处理不阻断）。
// @returns {Promise<number>} 进程退出码
async function runPurge(argv, inject = {}) {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const os = await import('node:os');
  const targets = inject.targets || [
    { label: '本地台账根目录（扫描快照 / 写副作用 / auth 审计）', path: scanLedger.ledgerRoot(), dir: true },
    { label: '引擎日志（本机 logs/）', path: path.join(process.cwd(), 'logs', 'engine.log'), bestEffort: true },
    { label: '引擎日志（临时目录）', path: path.join(os.tmpdir(), 'sqli-scanner', 'engine.log'), bestEffort: true },
  ];
  if (!argv.includes('--yes')) {
    if (!process.stdin.isTTY) {
      console.error('[purge] 非交互环境需显式 --yes 确认（将删除本地台账快照/审计与引擎日志；reports/ 与 --session-file 不受影响）');
      return 2;
    }
    const readline = await import('node:readline/promises');
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    const ans = (await rl.question('[purge] 将删除扫描器本地痕迹（台账快照/审计/引擎日志；reports/ 保留）。输入 yes 确认：')).trim();
    rl.close();
    if (ans !== 'yes') {
      console.error('[purge] 已取消');
      return 1;
    }
  }
  let removed = 0;
  for (const t of targets) {
    try {
      if (!fs.existsSync(t.path)) {
        console.log(`  - ${t.label}：不存在（跳过）`);
        continue;
      }
      fs.rmSync(t.path, { recursive: !!t.dir, force: true });
      removed++;
      console.log(`  ✔ ${t.label}：已删除 ${t.path}`);
    } catch (e) {
      if (t.bestEffort) {
        console.error(`  ⚠ ${t.label}：跳过（${e.message}）`);
        continue;
      }
      console.error(`  ✖ ${t.label}：删除失败 ${e.message}`);
      return 1;
    }
  }
  console.log(`[purge] 完成：删除 ${removed}/${targets.length} 项（reports/ 与 --session-file 未动）`);
  return 0;
}
export { runPurge };

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
        // ⚠ 这里是 os-shell / file-shell：**打印的是目标上执行命令的输出**，也就是
        // "被控端 → 操作员终端"这条最不该省防线的路径（对扫描器来说目标就是对手）。
        // 一条 OSC 8 就能在 Windows Terminal / iTerm / VTE 里造出"显示文字与真实地址不同"
        // 的可点击链接；OSC 0 改终端标题；CR/CSI 改写已经滚过去的结果行。
        // JSON.stringify 那一支天然安全（控制字符会被转成 \uXXXX），只有裸字符串这支要消毒。
        console.log(typeof out === 'string' ? sanitizeForTerminal(out) : JSON.stringify(out, null, 2));
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
        // [D44] evidence 透传结构化差分信号（向量被拦/连接级阻断/Server 头漂移）
        vendors.set(v, { vendor: v, confidence: probe.confidence, evidence: probe.evidence || 'active probe' });
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

/**
 * [D90 2026-10-18] `ledger side-effects` 子命令（写副作用查询与清理）。
 *
 * 抽成顶层函数而非内联在 main 里：main 是复杂度基线里的存量函数
 * （只许持平或变浅的棘轮），内联会让它 +38 行被门禁拦。
 * 这个函数职责单一：查登记表 → 打印清单与清理计划 → 可选执行清理。
 * @param {string[]} argvRaw 原始 argv（argvRaw[2]=scanId，含 '--cleanup' 时执行清理）
 */
/**
 * [D90] ledger side-effects 分派（在主分派链之外执行，返回 null 表示「不是本子命令」）。
 *
 * 为什么单独成一个函数、并用「取值表达式」而非 main 里的 if：
 *   main 位于复杂度棘轮基线上（只许持平或变浅），在它内部新增任何分支都会被门禁拦。
 *   把判断搬进独立函数后，main 只多一行取值表达式、零新增分支。
 * @param {string[]} argvRaw 原始 argv
 * @returns {Promise<string|null>} 命中时内部已执行并退出，返回 null（调用方随后用默认值占位）
 */
async function dispatchSideEffects(argvRaw) {
  if (argvRaw[1] !== 'side-effects') return null;
  await runSideEffectsSubcommand(argvRaw);
  process.exit(0);
}

async function runSideEffectsSubcommand(argvRaw) {
  const { readSideEffects, buildCleanupPlan } = await import('../src/services/sideEffectLedger.js');
  const id = argvRaw[2];
  if (!id || id.startsWith('--')) {
    console.error('用法: cli.js ledger side-effects <scanId> [--cleanup]');
    process.exit(1);
  }
  const doClean = argvRaw.includes('--cleanup');
  const store = readSideEffects(id);
  if (!store.effects.length) {
    console.log(`扫描 ${id} 无写副作用登记（未调用过写能力，或登记表不存在）`);
    process.exit(0);
  }
  console.log(`扫描 ${id} 的写副作用（登记于 ${store.createdAt || '-'}）：`);
  for (const e of store.effects) {
    const cleanMark = e.cleanedAt ? '✅已清理' : '⏳待清理';
    console.log(`  [${e.kind}] ${e.target}  ${e.status}  ${cleanMark}`);
    if (e.detail) console.log(`       ${e.detail}`);
  }
  const plan = buildCleanupPlan(id);
  console.log(`\n清理计划：应清理 ${plan.summary.应清理} · 不可逆 ${plan.summary.不可逆} · 已清理 ${plan.summary.已清理}`);
  for (const it of plan.items) console.log(`  → ${it.undo}`);
  for (const ir of plan.irreversible) {
    console.log(`  ⚠ 不可逆（需人工确认）: [${ir.kind}] ${ir.target}`);
  }
  if (!doClean) {
    console.log('\n（未执行清理。加 --cleanup 实际执行，且需 EXPLOIT_ENABLED=1）');
    process.exit(0);
  }
  // 执行侧同样受 EXPLOIT 门控：清理是对目标的又一次写/命令执行，不得绕门
  const { isExploitEnabled } = await import('../src/core/exploitFlag.js');
  if (!isExploitEnabled()) {
    console.error('清理需 EXPLOIT_ENABLED=1（它会对目标再发一次命令/写请求，属利用动作）');
    process.exit(2);
  }
  // CLI 不经引擎进程 ⇒ 没有可用的写通道；交由 REST 端点执行，避免出现第二条绕过门控的写链路
  console.error('⚠ 清理需经引擎的写/命令通道执行，请用 REST 端点 POST /api/exploit/side-effects/cleanup');
  console.error('   （CLI 不经引擎进程，避免出现第二条绕过门控的写链路）');
  process.exit(2);
}

/**
 * [D240 对标 sqlmap -t/--traffic-file] 开启原始流量落盘。
 * 启用失败**不阻断扫描**：流量文件是旁路审计能力，扫描结果比审计文件重要；
 * 但失败要在 stderr 可见（否则用户以为开了、其实一条没记）。
 * @param {any} args CLI 参数（读 trafficFile / trafficMaxBody）
 * @returns {void}
 */
function setupTrafficLog(args) {
  if (!args.trafficFile) return;
  try {
    const t = enableTrafficLog(args.trafficFile, {
      maxBody: Number.isFinite(args.trafficMaxBody) ? args.trafficMaxBody : undefined,
    });
    console.error(`  [traffic] 原始流量落盘：${t.file}（单条 body 上限 ${t.maxBody || '不限'} 字节；文件含完整请求头，按凭据文件保管）`);
  } catch (e) {
    console.error(`  [traffic] 开启失败（继续扫描）：${args.trafficFile}（${e?.message || e}）`);
  }
}

async function main() {
  // [D41 2026-10-11] --config 预扫：档案值作为参数底（argv 显式开关仍优先）。
  // 预扫必须在 parseArgs 之前 —— preset 要在 parseArgs 内部合并进 args 底。
  // 共享助手在 configFile.js（one-click-scan 同源复用，防两入口口径分叉）。
  const argvAll = process.argv.slice(2);
  let preset;
  try {
    preset = presetFromArgv(argvAll, parseArgs);
  } catch (e) {
    console.error(`[cli] ${e?.message || e}`);
    process.exit(2);
  }
  // [D240] 原始流量落盘：判断放在 setupTrafficLog 内（不给 main 加分支），调用与上一句同行
  const args = parseArgs(argvAll, preset); setupTrafficLog(args);
  // [D41] --save-config：把本次实际生效的参数增量（相对内置默认）落盘，然后照常继续扫描。
  if (args.saveConfigFile) {
    try {
      const n = saveConfigFile(args.saveConfigFile, args, parseArgs);
      console.log(`  [save-config] 已写 ${args.saveConfigFile}（${n} 个非默认参数）。复扫：node cli.js --config ${args.saveConfigFile}`);
    } catch (e) {
      console.error(`  [save-config] 写入失败：${args.saveConfigFile}（${e?.message || e}）`);
      process.exit(2);
    }
  }
  // [goal 批次 A-2] 台账检索子命令：node cli.js ledger list | ledger show <scanId>
  const argvRaw = process.argv.slice(2);
  // [UNKNOWN-FLAG 2026-09-25] 无法识别的开关 ⇒ 拒绝启动（判据与理由在 cli/args.js:unknownFlagError）。
  //   以前这些开关被静默吞掉：`--scope-typo 10.20.0.0/16` 会让红线整个消失而退出码仍是 0。
  //   台账子命令例外：它的 <scanId> 可能以 '-' 开头（nanoid 字母表含 -/_），不能按开关判。
  if (argvRaw[0] !== 'ledger') {
    const flagErr = unknownFlagError(args);
    if (flagErr) {
      console.error(flagErr);
      process.exit(2);
    }
  }
  if (argvRaw[0] === 'ledger') {
    const { listScans, getScan } = await import('../src/services/scanLedger.js');
    await dispatchSideEffects(argvRaw);
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
    // [2026-09-29] 手动运维入口：一次性收敛（不必常开自动策略）。
    // 参数优先于环境变量；两者都没给就拒绝执行 —— 默认必须是不删东西。
    if (sub === 'prune') {
      const { pruneLedger, retentionPolicy } = await import('../src/services/scanLedger.js');
      // [2026-09-29 收口] 等号与空格两种形态都要认：args.js 已把 --max/--days 登记为
      // 「已识别」（见 cli.unknownFlags.test.js），这里若只认 --max=<N>，空格形态会被
      // 静默忽略 —— 用户以为传上了，实际跑的是环境变量/默认值，比报错更糟。
      const argOf = (name) => {
        const eq = argvRaw.find((a) => a.startsWith(`--${name}=`));
        if (eq !== undefined) return eq.slice(name.length + 3) || null; // '--name=' 共 name+3 个字符
        const i = argvRaw.indexOf(`--${name}`);
        if (i !== -1) {
          const v = argvRaw[i + 1];
          if (v !== undefined && !v.startsWith('--')) return v;
        }
        return null;
      };
      const cur = retentionPolicy();
      const max = Number(argOf('max')) || cur.max;
      const maxDays = Number(argOf('days')) || cur.maxDays;
      if (!max && !maxDays) {
        console.error('未指定保留策略：用 ledger prune --max=<N> / --days=<N>，或设置 SCAN_LEDGER_MAX / SCAN_LEDGER_MAX_DAYS');
        process.exit(2);
      }
      const r = pruneLedger({ policy: { max, maxDays } });
      console.log(`台账清理：保留 ${r.kept} 条，删除 ${r.removed} 条`);
      if (r.removedIds.length) console.log(`  已删除: ${r.removedIds.join(', ')}`);
      if (r.failed.length) {
        console.log(`  删除失败 ${r.failed.length} 条: ${r.failed.map((f) => `${f.id}(${f.error})`).join(', ')}`);
      }
      process.exit(r.failed.length ? 1 : 0);
    }
    console.error(`未知子命令: ledger ${sub}（支持 list / show / prune / side-effects）`);
    process.exit(1);
  }
  // [D43 2026-10-11] MCP server 模式（对标 dalfox mcp / semgrep mcp：「MCP 是 CLI 的一个模式」）：
  //   node cli.js mcp —— stdio NDJSON，供 AI 代理宿主（Cursor/Claude/VS Code 等）直连。
  //   必须在 help/url 门之前接管（mcp 是子命令不是旗标，parseArgs 会把它当无值噪音）。
  if (argvRaw[0] === 'mcp') {
    // [D90 补偿] 合并两行为一行：为 ledger side-effects 分派腾出 1 行额度（本仓棘轮不许涨基线）
    await (await import('../src/mcp/index.js')).runMcpStdio(), process.exit(0);
  }
  // 对标 sqlmap -r：请求文件优先于 -u，先应用再校验目标参数
  if (args.requestFile && !applyRequestFile(args)) process.exit(1);
  // 对标 sqlmap -l / -m：日志文件与批量文件同样可替代 -u
  if (args.help || (!args.url && !args.batch && !args.direct && !args.logFile)) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }
  // [2026-10-12 优化空间勘查 §A3] --format 早校验：格式非法必须在**发起任何扫描之前**拒绝。
  // formatReport 内的硬拒是最后防线（防"传了没生效"），但只在落盘那一刻触发 ⇒ 扫完几十分钟
  // 才崩。这里提前到入口，与 --config 未知键硬拒同一条政策（宁可拒绝启动，不静默降级）。
  {
    const fmt = String(args.format || 'json').toLowerCase();
    if (!['json', 'csv', 'markdown', 'md', 'html', 'sarif', 'db-json'].includes(fmt)) {
      console.error(`[cli] --format 未知格式：${args.format}（仅支持 json|csv|markdown|md|html|sarif|db-json）`);
      process.exit(2);
    }
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
  // [D24 2026-10-09 扩展生态] 自定义检测条目：硬失败优先（静默忽略比报错危险 —— 用户会以为生效了）
  if (args.payloadFile) {
    try {
      const parsed = JSON.parse(readFileSync(args.payloadFile, 'utf8'));
      const { entries, errors } = validateCustomEntries(parsed);
      if (errors.length > 0) {
        console.error(`  [payload-file] ${args.payloadFile} 校验失败，不继续扫描：\n    - ${errors.join('\n    - ')}`);
        process.exit(2);
      }
      // 冲突检查（与内置 id 比对）；不允许覆盖内置条目，抛错即拒
      mergeCustomEntries(PAYLOAD_REGISTRY, entries);
      args.payloadEntries = entries;
      console.log(`  [payload-file] 已追加 ${entries.length} 条自定义条目（${args.payloadFile}），仅本次扫描生效`);
    } catch (e) {
      console.error(`  [payload-file] 加载失败：${args.payloadFile}（${e?.message || e}）`);
      process.exit(2);
    }
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
    // [2026-10-02 竞品合并] `-m` 从「只认一行一个 URL」扩到「也认请求集合」
    // （Burp XML / HAR / Postman / OpenAPI JSON）—— 对标 sqlmap 2.0 的 OpenAPI 目标生成。
    // 此前这三样各在一处：集合解析归 `-r`（且只取第 1 条、其余打一句"请拆分文件"），
    // 多目标归 `-m`（只吃文本 URL），刚补的并发池归 batchPool —— 接口清单这条最省事的
    // 批量入口因此一直是断的。现在合流：集合 → N 个目标 → 批量池。
    const { readFileSync: readBatchFile } = await import('node:fs');
    const { expandBatchTargets, scanArgsFromRequest } = await import('./cli/batchTargets.js');
    const expanded = expandBatchTargets(readBatchFile(args.batch, 'utf-8'));
    const isCollection = expanded.kind === 'collection';
    const urls = expanded.items;
    // 「识别成什么格式、展开出几个目标」必须说出来：静默降级是本仓反复踩的坑
    // （"根本没测"会被读成"测了且安全"）。
    console.error(
      `批量目标来源：${isCollection ? `请求集合（${expanded.format}）` : 'URL 列表'} ⇒ 展开 ${urls.length} 个目标`,
    );
    for (const w of expanded.warnings) console.error(`  [提示] ${w}`);
    if (!urls.length) {
      console.error('批量目标为空：URL 列表模式下每行须为 http(s) 地址；集合模式下未解析出可用请求。');
      process.exit(1);
    }
    // 集合条目是对象（带 method/headers/body），URL 列表是字符串 —— 打印与落盘取名的统一入口
    const urlOf = (it) => (it && typeof it === 'object' ? String(it.url || '') : String(it || ''));
    // [2026-10-03 共享组桶] 全局限速从「启动时均分」改为「整批共用一个令牌桶」。
    //   旧方案：每扫描 ratePerSec = 总/并发，在批量启动那一刻算死 ⇒ 队列排空后剩下的目标
    //   仍按 1/并发度 跑（并发 8、剩 1 个目标时它只有 1/8 预算，7/8 白白闲着）。
    //   新方案：所有目标共用 rateGroup 桶，桶的速率就是总速率 ⇒
    //     ① 总速率严格 ≤ ratePerSec —— 由**单桶**保证，不依赖均分算得准不准；
    //     ② 谁在用谁就能拿到预算 —— 排空后剩下的目标自动吃满，无需运行期改桶速率。
    //   ⚠ ratePerSec<=0（--rate 0 = 不限速）时组桶也是不限速，语义不变。
    const rateGroup = `batch-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    console.error(`批量扫描 ${urls.length} 个目标，并发 ${args.concurrency}，共享限速桶（总 ≤ ${args.ratePerSec} req/s，谁在用谁拿，排空后自动吃满）`);
    // [P1-2] 共享 HttpClient：批量模式所有 ScanManager 共用同一个 httpClient 单例
    // → 组桶就建在这同一个 buckets Map 上（原实现每 URL new ScanManager，但 ScanManager
    //   构造器已用模块级 httpClient 单例，实际已共享；此注释确认此行为是正确设计而非巧合）
    // 并发池：按 args.concurrency 限制并发数（故障隔离见 cli/batchPool.js）
    const { runBatch } = await import('./cli/batchPool.js');
    const batchT0 = Date.now();
    const { results, failures, needsReview, summary } = await runBatch({
      urls,
      concurrency: args.concurrency,
      labelOf: urlOf,
      scanOne: async (item) => {
        const sm = new ScanManager();
        // 集合条目自带 method/headers/body ⇒ 逐目标派生（与 -l 同一映射口径）；
        // URL 列表只有地址，沿用 args。两种形态都吃同一个均分速率。
        // 组桶要求**所有成员传同一个 ratePerSec**（桶由第一个建桶者决定速率）⇒ 这里用总速率，
        // 不再除以并发度 —— 总量由共享桶兜住。
        const scanArgs = isCollection
          ? { ...scanArgsFromRequest(args, item), rateGroup }
          : { ...args, rateGroup };
        return runSingleScan(sm, urlOf(item), scanArgs);
      },
      // 扫完了 ≠ 测过了：0 注入点（目标不通 / URL 没参数）时报告照样产出，但一个检测请求都没发，
      // 结论是 inconclusive —— 批量里必须把这类目标单独点名，否则"100 个站点全绿"里可能
      // 有 30 个根本没连上。
      audit: (report) => (report?.points?.length === 0
        ? '未发现可测注入点（一个检测请求都没发）：确认目标可达、URL 是否带参数，或改用 --body / --xml-body 指定注入面'
        : null),
    });

    // [D196] 批量收场摘要整块（呈现层移至 cli/summaryPanel.js）：汇总+耗时/风险分布/
    // 命中目标点名/失败点名/需复核对点名/下一步。点名语义见 batchPool.runBatch 注释。
    printBatchSummary({ title: '批量扫描完成', summary, results, urlOf, failures, needsReview, startedAt: batchT0 });

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      // 扩展名与 REST FORMAT_EXT 对齐（md 别名归一；db-json → db.json）
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt === 'db-json' ? 'db.json' : fmt;
      for (const r of results) {
        if (r.report) {
          // 同名目标（集合里同 URL 不同 method）会互相覆盖 ⇒ 名字里带上方法，避免"少一份报告"
          const nameBase = isCollection && r.url?.method ? `${urlOf(r.url)} ${r.url.method}` : urlOf(r.url);
          const safeName = nameBase.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
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
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}${batchWriteHint(fmt)}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: urlOf(r.url), riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }

    // 退出码：有高危 → 2（既有语义不变）；**全批失败 → 1**（与"扫了但没高危"区分：
    // 前者是编排/目标不可达，后者是结论）。部分失败仍为 0 —— 失败已在摘要里点名。
    if (summary.allFailed) process.exit(1);
    process.exit(summary.hasHigh ? 2 : 0);
  }

  // ---- 日志文件批量模式（对标 sqlmap -l） ----
  if (args.logFile) {
    const requests = parseLogFile(args.logFile);
    if (requests.length === 0) {
      console.error('日志文件未解析出任何请求（支持 Burp XML 导出或纯文本多请求日志）');
      process.exit(1);
    }
    // [2026-10-03] 与 -m 同一口径：共享组桶（谁在用谁拿），不再按并发度均分。
    const rateGroup = `batch-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    console.error(`日志批量 ${requests.length} 个请求，并发 ${args.concurrency}，共享限速桶（总 ≤ ${args.ratePerSec} req/s，排空后自动吃满）`);
    const { runBatch } = await import('./cli/batchPool.js');
    const logBatchT0 = Date.now();
    const { results, failures, summary } = await runBatch({
      urls: requests,
      concurrency: args.concurrency,
      scanOne: async (req) => {
        const sm = new ScanManager();
        // 每请求从 args 派生扫描参数：覆盖 url/method/body/headers/cookie（复用 -r 的字段映射逻辑）
        const scanArgs = { ...args, rateGroup };
        scanArgs.url = req.url;
        scanArgs.method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? req.method : 'GET';
        if (req.body) {
          const bodyJson = bodyToJsonString(req.body);
          if (bodyJson) scanArgs.body = bodyJson;
        }
        const cookieKey = Object.keys(req.headers).find((k) => k.toLowerCase() === 'cookie');
        if (cookieKey) scanArgs.cookie = req.headers[cookieKey];
        const other = {};
        for (const [k, v] of Object.entries(req.headers)) {
          const kl = k.toLowerCase();
          if (kl === 'cookie' || kl === 'host' || kl === 'content-length') continue;
          other[k] = v;
        }
        if (Object.keys(other).length) scanArgs.headerObj = other;
        return runSingleScan(sm, req.url, scanArgs);
      },
    });

    // [D196] 批量收场摘要（与 -m 同口径，呈现层整块在 cli/summaryPanel.js）
    printBatchSummary({ title: '日志批量扫描完成', summary, results, urlOf: urlOfLogRequest, failures, startedAt: logBatchT0 });

    if (args.out) {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');
      mkdirSync(args.out, { recursive: true });
      // [P1-FIX 2026-09-05] 批量模式同样按 --format 分发（每 URL 一份，扩展名随格式）
      const fmt = String(args.format || 'json').toLowerCase();
      // 扩展名与 REST FORMAT_EXT 对齐（md 别名归一；db-json → db.json）
      const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt === 'db-json' ? 'db.json' : fmt;
      for (const r of results) {
        if (r.report) {
          const safeName = r.url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
          writeFileSync(join(args.out, `${safeName}.${ext}`), formatReport(r.report, fmt), 'utf-8');
        }
      }
      console.error(`报告已写入 ${args.out}/（格式 ${fmt}${batchWriteHint(fmt)}）`);
    } else {
      console.log(JSON.stringify(results.map(r => ({ url: r.url, riskLevel: r.riskLevel, vulns: r.vulns })), null, 2));
    }
    // 与 -m 同口径：全批失败 → 1，有高危 → 2，部分失败仍 0（失败已点名）
    if (summary.allFailed) process.exit(1);
    process.exit(summary.hasHigh ? 2 : 0);
  }

  // ---- 单目标模式（HTTP 或直连） ----
  const sm = new ScanManager();
  const report = await runSingleScan(sm, args.direct || args.url, args);
  if (!report) {
    console.error('扫描超时或报告不存在');
    process.exit(1);
  }

  const exploitMode = isPostScanMode(args);
  // [D177] 复现检查必须在出报告之前：判定要进 report.json / manifest，不能事后补
  if (args.reproCheck) await applyReproCheck(report, args);
  await emitSingleScanOutput(report, args, { enumActive, exploitMode });

  // 攻击操作与清理（对标 sqlmap --os-cmd/--sql-shell/--file-read/--file-write/--reg-*/--cleanup）：
  // 需 EXPLOIT_ENABLED=1 + --authorized；对首个命中注入点执行并打印结果
  if (exploitMode) {
    await runPostScanActions(report, args);
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
  // [D132] -V/--version：入口元信息查询，在 parseArgs 之前接管。旧行为是
  // `--version` 被判成「无法识别的参数」直接 exit 2（发包/排障第一步就问版本）。
  // 放在 main() 之外有两个理由：① 版本查询不该要求 -u；② main() 是复杂度基线里的
  // 存量函数（只许持平），多一个分支就会顶破基线。
  if (process.argv.includes('--version') || process.argv.includes('-V')) await printVersion();
  // [D197 2026-10-30 对标 sqlmap --list-tampers] 插件清单同样是**入口元信息查询**：
  // 不要求 -u、不发包、不进扫描流程。与 --version 同一形态、同一理由放在 main() 之外
  // （main 的复杂度是存量基线，加分支就得抬基线 —— 纪律禁止）。
  // 覆盖它的门禁是 scripts/sqlmap-parity.mjs（把本行的字面量算作「本方旗标真源」之一）；
  // ⑯/⑰ 旗标门禁只认 args.js 的解析分支，故 README/help 的收录由本轮手动保证。
  if (process.argv.includes('--list-tampers')) await printTamperCatalog();
  // [D198 对标 sqlmap --purge] 本地痕迹清理：与 --version 同形态的入口元信息动作，
  // 不要求 -u、不进扫描流程、不发包；放 main() 之外同因（main 是存量复杂度基线）。
  if (process.argv.includes('--purge')) {
    process.exit(await runPurge(process.argv));
  }
  main().catch((e) => {
    logger.error(`CLI 执行失败：${e.message}`);
    console.error(e.message);
    process.exit(1);
  });
}

// 导出供单测使用（仍在 cli.js 定义的符号；args 族的再导出见文件顶部）
export { buildConfig, isEnumMode, buildExtractScope, validateEnumArgs, runSingleScan, buildInjectionTargets, resolveBodyChannel };
// 注：runExploit 已在定义处 `export async function` 导出，**不可**在此再列一次
// （重复导出会被 module-loadable 门禁拦下：它会让整个 CLI 无法加载）。

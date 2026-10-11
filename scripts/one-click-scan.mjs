#!/usr/bin/env node
// ============================================================================
// one-click-scan.mjs —— 一键式扫描 + 全套结构化报告产出（交付层主入口）
// ============================================================================
// 解决什么问题（实测缺口）：
//   现状下要拿到一份完整交付物，需要「先起 REST 服务 → 再调 CLI → 或手工拼 --format」，
//   且一次只落一种格式；server/one-click-scan.mjs 更是只把结果打在 stdout、不落盘。
//   本脚本把「目标校验 → 扫描 → 全套报告落盘 → 机器可读清单」压成**一条命令**：
//
//     node scripts/one-click-scan.mjs -u "http://target/page?id=1"
//
//   产出目录（默认 reports/<host>-<时间戳>/）：
//     report.html    人读交付物（含执行摘要/漏洞清单/PoC/修复建议/WAF 交战）
//     report.json    机器可读完整报告（含逐条 PoC 证据链）
//     report.md      Markdown 交付物（可贴进工单/知识库）
//     report.sarif   SARIF 2.1.0（对接 GitHub Security / DefectDojo，可选）
//     report.csv     漏洞表 + 拖库数据（Excel 可开，可选）
//     manifest.json  本次扫描的结构化清单（元信息 + 漏洞索引 + 文件清单 + 授权声明）
//
// 设计约束：
//   - **零重复实现**：参数解析复用 server/bin/cli/args.js，配置构建复用 cli/config.js，
//     扫描编排复用 bin/cli.js 的 runSingleScan（scope 登记 / 进度事件 / 终态轮询全在其中），
//     报告渲染复用 ReportGenerator。本文件的职责只有「编排 + 落盘 + 摘要」。
//   - **不预启动 REST 服务**：直接持有 ScanManager，一条命令即可跑（对标 sqlmap 的调用形态）。
//   - 退出码对标 CI 门禁：Critical/High → 2，其余 → 0，执行失败 → 1。
// ============================================================================

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ScanManager } from '../server/src/engine/ScanManager.js';
import { ReportGenerator } from '../server/src/services/ReportGenerator.js';
// [D42 2026-10-11 对标 sqlmap --dump-format] 拖库数据独立产物格式化（27 条既有单测钉行为）
import { formatDumpData } from '../server/src/engine/dumpFormat.js';
// [D45 2026-10-11] diff-aware CI 门禁：diff 计算与 REST /api/scan/:id/diff 同源（scanDiff），
// 基线解析与退出码裁决在 diffGate（纯函数，单测钉死三种出口）
import { diffReports } from '../server/src/engine/scanDiff.js';
import { findBaselineScanId, resolveBaselineReport, decideDiffExit } from '../server/src/services/diffGate.js';
import { cvssFor } from '../server/src/services/reportDelivery.js';
import { VULN_TAXONOMY } from '../server/src/services/vulnTaxonomy.js';
import { parseScope } from '../server/src/core/scopeGuard.js';
// 生效配置的兜底展示值：buildConfig 只在显式传参时写入 level/risk，
// 未传时真实生效的是 defaults（level=1 / risk=2）。若此处凭空补 1，会把「risk=2（含
// time/stacked/oob）」误报成「risk=1」，交付摘要与报告正文自相矛盾——故从同一源头取。
import { defaults as DEFAULT_CONFIG } from '../server/src/config/defaults.js';
import * as scanLedger from '../server/src/services/scanLedger.js';
import { buildConfig } from '../server/bin/cli/config.js';
import { parseArgs, applyRequestFile, resolveTamperPlugins, unknownFlagError } from '../server/bin/cli/args.js';
// [D41 2026-10-11] 配置档案：与 bin/cli.js 同源预载（--config）/落盘（--save-config），
// 防两入口口径分叉 —— one-click 是 CI 入口，静默忽略 --config 比报错危险。
import { presetFromArgv, saveConfigFile } from '../server/bin/cli/configFile.js';
import { runSingleScan } from '../server/bin/cli.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

// 支持的输出格式 → 渲染函数（未知格式在入口处被拒，不做静默回退：交付物格式必须确定）
const FORMATS = ['html', 'json', 'markdown', 'sarif', 'csv'];
const DEFAULTS_FORMATS = ['html', 'json', 'markdown'];

const AUTHORIZATION_NOTE =
  '本报告仅供授权安全测试使用；未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规。';

// ---------------------------------------------------------------------------
// 自定义参数（不污染 parseArgs 的既有键表：先摘出来，其余原样交给 CLI 解析器）
// ---------------------------------------------------------------------------
function splitOwnArgs(argv) {
  const opts = { formats: [...DEFAULTS_FORMATS], ledger: true, quiet: false, open: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--formats' || a === '-F') {
      const v = String(argv[++i] || '');
      const list = v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
      const bad = list.filter((f) => !FORMATS.includes(f));
      if (bad.length) return { opts, rest, error: `--formats 含不支持的格式：${bad.join(', ')}（支持 ${FORMATS.join('/')}）` };
      if (list.length) opts.formats = list;
      continue;
    }
    if (a === '--no-ledger') { opts.ledger = false; continue; }
    if (a === '--quiet') { opts.quiet = true; continue; }
    // [D45 2026-10-11] diff-aware CI 门禁（semgrep 语义）：--diff-base <scanId|auto>，
    // 只对新增发现判红（exit 2），存量发现不阻塞（exit 0），结论不可信 → exit 1。
    if (a === '--diff-base') {
      const v = String(argv[++i] || '').trim();
      if (!v) return { opts, rest, error: '--diff-base 需要值：<baselineScanId> 或 auto（按目标自动找台账里最近一次同目标扫描）' };
      if (v !== 'auto' && !/^[A-Za-z0-9_-]{1,64}$/.test(v)) {
        return { opts, rest, error: `--diff-base 形态非法：${v}（scanId 只认 [A-Za-z0-9_-]{1,64}，或 auto）` };
      }
      opts.diffBase = v;
      continue;
    }
    rest.push(a);
  }
  return { opts, rest, error: null };
}

function printHelp() {
  const techniques = Object.values(VULN_TAXONOMY).map((t) => `    ${t.key.padEnd(13)} ${t.nameZh}（${t.cwe}）`).join('\n');
  console.log(`sqli-scanner 一键扫描（扫完自动产出全套结构化报告）

用法:
  node scripts/one-click-scan.mjs -u <url> [选项]
  node scripts/one-click-scan.mjs -r <请求文件> [选项]      # 从 Burp/curl 请求导入（对标 sqlmap -r）
  node scripts/one-click-scan.mjs -d <连接串> --sql-template '<SQL 含 {INJECT}>'

本脚本专属选项:
  -F, --formats <list>   输出格式，逗号分隔（默认 html,json,markdown；可选 sarif,csv）
      --diff-base <id|auto>  diff 门禁（[D45] semgrep 语义：只对新增发现判红）。与基线扫描
                             比对（auto=台账中最近一次同目标扫描），新增发现 → exit 2；
                             存量仍在 → exit 0（不阻塞无关 PR）；本次结论不可信或无基线可认
                             → exit 1（拒绝认证，不假绿）。产出 diff.json + manifest.diff
  -o, --out <dir>        输出目录（默认 reports/<主机名>-<时间戳>/）
      --no-ledger        不写扫描台账快照
      --quiet            精简输出（只打最终摘要）
  -h, --help             显示本帮助

扫描选项（与 bin/cli.js 完全一致，常用项）:
  -u, --url <url>              目标 URL
  -r, --request-file <file>    请求文件（优先于 -u）
      --method <GET|POST|...>  请求方法
      --body <json>            请求体（JSON 对象字符串）
      --cookie <str>           认证 Cookie（会话透传，非注入点）
      --header <k:v,k:v>       额外请求头
      --technique <list>       检测技术子集（缺省按引擎推荐）
      --level <1-5>            检测等级（默认 1）
      --risk <1-3>             风险等级（默认 1）
      --tamper <list>          tamper 插件链（WAF 绕过）
      --scope <list>           授权范围（域名/CIDR 白名单；缺省按目标同源执行）
      --proxy <url>            代理（如 http://127.0.0.1:7890）
      --timeout <ms>           扫描超时（默认 0 = 不限）
      --test-headers           把请求头作为注入点测试
      --test-path              把 URL path 末段作为注入点测试
  -p, --test-param <p1,p2>     只测指定参数（对标 sqlmap -p；复测/CI 定向回归）
      --param-exclude <regex>  按正则排除参数（对标 sqlmap --param-exclude）
      --param-filter <places>  按位置筛选（url/body/header/cookie/path，对标 sqlmap --param-filter）
      --second-req <file>      二阶触发页整请求文件（对标 sqlmap --second-req；POST/头/Cookie 触发页）
      --ignore-code <codes>    忽略指定 HTTP 错误码（对标 sqlmap --ignore-code）
      --randomize <params>     注入请求随机化指定参数值（对标 sqlmap --randomize，防锁定）
      --dump-format <fmt>      拖库数据独立产物格式 csv/sql/html/json（对标 sqlmap --dump-format）
      --config <file.json>     从配置档案预载参数（argv > 档案 > 默认；未知键拒绝启动）
      --save-config <file>     把本次非默认参数增量落盘，下次 --config 复扫
      --dump / --dbs ...       数据提取（显式 opt-in，对标 sqlmap）

支持的注入类型（引擎内置技术通道）:
${techniques}

退出码: 0=未发现高危 / 2=发现 Critical 或 High / 1=执行失败（可直接用于 CI 门禁）`);
}

// ---------------------------------------------------------------------------
// 摘要打印
// ---------------------------------------------------------------------------
function riskTag(level) {
  const s = String(level || '').toLowerCase();
  if (s === 'critical') return '[严重]';
  if (s === 'high') return '[高危]';
  if (s === 'medium') return '[中危]';
  if (s === 'low') return '[低危]';
  return '[--]';
}

function printReportBrief(report, files, outDir) {
  const vulns = Array.isArray(report.vulns) ? report.vulns : [];
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  扫描结果');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`  目标      : ${report.target?.baseUrl || '-'}`);
  console.log(`  扫描 ID   : ${report.scanId}`);
  console.log(`  风险等级  : ${report.riskLevel}    数据库: ${report.dbms || '未识别'}`);
  console.log(`  注入点    : ${(report.points || []).length} 个    漏洞: ${vulns.length} 条`);
  const validity = report.summary?.validity;
  if (validity) console.log(`  结论可信度: ${validity.status}${validity.reliable === false ? '（不可信，请查阅报告）' : ''}`);
  const skipped = report.summary?.skippedPoints;
  if (skipped && skipped.total) console.log(`  未测注入点: ${skipped.total} 个（原因见报告「结论可信度」小节）`);

  if (vulns.length) {
    console.log('');
    console.log('  漏洞清单（类型 / 受影响参数 / 风险）:');
    for (const v of vulns) {
      const t = v.vulnType || {};
      const param = v.affectedParam || v.param || '（未记录参数名）';
      const cvss = cvssFor(v);
      console.log(`    ${riskTag(v.riskLevel)} ${t.nameZh || v.technique} · ${t.cwe || '-'}`);
      console.log(`            受影响参数: ${param}`);
      console.log(`            技术通道  : ${v.technique}    风险: ${v.riskLevel} (CVSS ${cvss.score})`);
      if (v.poc?.curl) console.log(`            利用证明  : ${String(v.poc.curl).slice(0, 100)}${v.poc.curl.length > 100 ? '…' : ''}`);
    }
  } else {
    console.log('  未检出漏洞（注意核对「结论可信度」：未检出 ≠ 不存在）');
  }

  console.log('');
  console.log('  产出文件:');
  for (const f of files) console.log(`    ${f}`);
  console.log(`  目录: ${outDir}`);
  console.log('');
  console.log(`  ⚠ ${AUTHORIZATION_NOTE}`);
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
async function main() {
  const argv = process.argv.slice(2);
  const { opts, rest, error } = splitOwnArgs(argv);
  if (error) { console.error(error); process.exit(1); }

  if (rest.includes('-h') || rest.includes('--help')) { printHelp(); process.exit(0); }

  // [D41 2026-10-11] --config 预载（与 bin/cli.js 同一助手/同一硬拒），argv 显式开关仍优先
  let preset;
  try {
    preset = presetFromArgv(rest, parseArgs);
  } catch (e) {
    console.error(`[one-click] ${e?.message || e}`);
    process.exit(2);
  }
  const args = parseArgs(rest, preset);
  // [UNKNOWN-FLAG 2026-09-25] 与 bin/cli.js 同一道硬拒：一键扫描是给 CI/工单用的入口，
  //   拼错的开关若被静默吞掉（尤其 --scope / --authorized），退出码 0 就成了假安全。
  {
    const flagErr = unknownFlagError(args);
    if (flagErr) {
      console.error(flagErr);
      process.exit(2);
    }
  }
  // [D41] --save-config：把本次实际生效参数增量落盘后照常扫描（与 bin/cli.js 同语义）
  if (args.saveConfigFile) {
    try {
      const n = saveConfigFile(args.saveConfigFile, args, parseArgs);
      console.log(`  [save-config] 已写 ${args.saveConfigFile}（${n} 个非默认参数）。复扫：node scripts/one-click-scan.mjs --config ${args.saveConfigFile}`);
    } catch (e) {
      console.error(`  [save-config] 写入失败：${args.saveConfigFile}（${e?.message || e}）`);
      process.exit(2);
    }
  }
  // -r 优先于 -u（与 bin/cli.js 同语义）：先应用请求文件再校验目标
  if (args.requestFile && !applyRequestFile(args)) { console.error('请求文件解析失败'); process.exit(1); }
  if (!args.url && !args.direct) {
    console.error('缺少目标：请用 -u <url>（或用 -r/-d）。\n');
    printHelp();
    process.exit(1);
  }
  if (args.tamper) {
    try { args.tamperResolved = await resolveTamperPlugins(args.tamper); }
    catch (e) { console.error(`tamper 插件加载失败：${e.message}`); process.exit(1); }
  }

  const target = args.direct ? `直连:${args.direct}` : args.url;
  const cfg = buildConfig(args);
  const scopeRules = parseScope(args.scope ? String(args.scope).split(',').map((s) => s.trim()) : []);

  if (!opts.quiet) {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('  sqli-scanner 一键扫描');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`  目标      : ${target}`);
    console.log(`  请求方法  : ${args.method || 'GET'}`);
    console.log(`  检测配置  : level=${cfg.level ?? DEFAULT_CONFIG.level} · risk=${cfg.risk ?? DEFAULT_CONFIG.risk} · 技术=${cfg.techniques ? cfg.techniques.join('/') : '引擎按 risk 自动选池'}`);
    console.log(`  测试范围  : ${scopeRules.enabled ? scopeRules.raw.join(', ') : '未显式配置——按「目标 URL 同源」口径执行'}`);
    console.log(`  输出格式  : ${opts.formats.join(', ')}`);
    console.log(`  ⚠ ${AUTHORIZATION_NOTE}`);
    console.log('');
  }

  const sm = new ScanManager();
  const t0 = Date.now();
  const report = await runSingleScan(sm, args.direct || args.url, args);
  if (!report) { console.error('扫描未产出报告（超时或引擎错误）'); process.exit(1); }

  // ---- 报告落盘 ----
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const hostOf = (() => {
    try { return new URL(args.url).hostname.replace(/[^a-zA-Z0-9.-]/g, '_'); } catch { return 'direct'; }
  })();
  const outDir = resolve(ROOT, args.out || join('reports', `${hostOf}-${ts}`));
  mkdirSync(outDir, { recursive: true });

  const rg = new ReportGenerator();
  const renderers = {
    html: [['report.html', () => rg.toHTML(report)]],
    json: [['report.json', () => rg.toJSON(report)]],
    markdown: [['report.md', () => rg.toMarkdown(report)]],
    sarif: [['report.sarif', () => rg.toSARIF(report)]],
    csv: [['report.csv', () => rg.toCSV(report)]],
  };
  const files = [];
  for (const fmt of opts.formats) {
    for (const [name, render] of renderers[fmt]) {
      writeFileSync(join(outDir, name), render(), 'utf-8');
      files.push(name);
    }
  }

  // [D42 2026-10-11 对标 sqlmap --dump-format] 拖库数据独立产物：config.dumpFormat（csv/sql/html/json）
  // 配置且有拖库数据时写 dump.<ext>。此前 dumpFormat 四个格式化函数与 27 条测试早已存在，
  // 但链路从未接通（Extractor.js 头部注释自证「ctx.config.dumpFormat 都未被接线」）。
  // 边界：只影响**独立产物文件**，报告内嵌的拖库区（数据提取树 / report.csv 内嵌表）不变。
  if (cfg.dumpFormat) {
    const rows = report.data?.rows || {};
    const tables = Object.entries(rows).filter(([, arr]) => Array.isArray(arr) && arr.length);
    if (tables.length) {
      const parts = tables.map(([table, arr]) =>
        String(formatDumpData(arr, Object.keys(arr[0]), table, cfg.dumpFormat))
      );
      let content = parts.join('\n');
      if (cfg.dumpFormat === 'csv') content = '\uFEFF' + content; // Excel BOM（与 report.csv 同口径）
      const dumpName = `dump.${cfg.dumpFormat}`;
      writeFileSync(join(outDir, dumpName), content, 'utf-8');
      files.push(dumpName);
    }
  }

  // [D45 2026-10-11] diff-aware CI 门禁（semgrep 语义）：--diff-base 给出时，与基线扫描
  // 比 diff（与 REST /api/scan/:id/diff 同源 scanDiff 模块），**只对新增发现判红**——
  // 存量发现已暴露在基线里，不该阻塞无关 PR。结论不可信（validity.reliable=false）→ exit 1
  //（不判红也不假绿：verdict=inconclusive ≠ 未检出）。无基线可认 → exit 1（拒绝认证）。
  let diffInfo = null;
  if (opts.diffBase) {
    const rows = scanLedger.listScans(500);
    const curTarget = report.target?.url || report.target?.baseUrl || target;
    const baseScanId = findBaselineScanId({
      diffBase: opts.diffBase,
      currentScanId: report.scanId,
      currentTarget: curTarget,
      rows,
    });
    if (!baseScanId) {
      console.error(
        `[diff-gate] 找不到基线扫描（--diff-base ${opts.diffBase}` +
        `${opts.diffBase === 'auto' ? '：台账中无同目标历史扫描' : ''}）。` +
        '\n  门禁拒绝在无基线时认证「无新增」——先跑一次建立基线（同一目标 URL），或显式给出基线 scanId。'
      );
      process.exit(1);
    }
    const baseReport = resolveBaselineReport({ baseScanId, scanManager: null });
    if (!baseReport) {
      console.error(`[diff-gate] 基线扫描 ${baseScanId} 的报告不可读（台账缺失/损坏）——门禁拒绝认证`);
      process.exit(1);
    }
    const diff = diffReports(baseReport, report);
    const decision = decideDiffExit({ diff, newReport: report });
    diffInfo = { baseScanId, diff, decision };
    writeFileSync(join(outDir, 'diff.json'), JSON.stringify(diff, null, 2), 'utf-8');
    files.push('diff.json');
  }

  // ---- 结构化清单（机器消费入口：CI / 工单系统 / 汇总看板）----
  const pocReport = (() => { try { return rg.attachPoc(report); } catch { return report; } })();
  const manifest = {
    tool: 'sqli-scanner',
    generator: 'scripts/one-click-scan.mjs',
    scanId: report.scanId,
    target: report.target?.baseUrl || target,
    method: report.target?.method || args.method || 'GET',
    scope: scopeRules.enabled ? '显式授权范围' : '目标 URL 同源',
    startedAt: report.startedAt || null,
    finishedAt: report.finishedAt || null,
    durationMs: Date.now() - t0,
    riskLevel: report.riskLevel,
    dbms: report.dbms || null,
    summary: {
      totalPoints: (report.points || []).length,
      totalVulns: (report.vulns || []).length,
      byRisk: report.summary?.byRisk || null,
      byTechnique: report.summary?.byTechnique || null,
      validity: report.summary?.validity || null,
      dbmsEvidence: report.summary?.dbmsEvidence || null,
    },
    findings: (pocReport.vulns || []).map((v) => ({
      id: v.id,
      pointId: v.pointId,
      // —— 交付四要素：漏洞类型 / 风险等级 / 受影响参数 / 利用证明 ——
      vulnType: v.vulnType || null,
      riskLevel: v.riskLevel,
      cvss: cvssFor(v),
      affectedParam: v.param || null,
      affectedLocation: v.location || null,
      affectedRequest: v.url ? `${v.method || 'GET'} ${v.url}` : null,
      technique: v.technique,
      dbms: v.dbms || null,
      payloads: v.payloads || [],
      poc: v.poc
        ? { method: v.poc.method, url: v.poc.url, payload: v.poc.payload, curl: v.poc.curl, raw: v.poc.raw }
        : null,
    })),
    files: files.map((f) => join(outDir, f)),
    // [D45] diff 门禁结果（--diff-base 给出时）：机器消费的「新增计数 + 裁决原因」
    diff: diffInfo
      ? {
          baseScanId: diffInfo.baseScanId,
          baselineVulns: diffInfo.diff.base.vulnCount,
          added: diffInfo.diff.new.length,
          fixed: diffInfo.diff.fixed.length,
          remaining: diffInfo.diff.remaining.length,
          summary: diffInfo.diff.summary,
          decision: { code: diffInfo.decision.code, reason: diffInfo.decision.reason },
        }
      : null,
    authorization: AUTHORIZATION_NOTE,
  };
  writeFileSync(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf-8');
  files.push('manifest.json');

  // ---- 扫描台账（可追溯快照，`node server/bin/cli.js ledger list` 可查）----
  if (opts.ledger) {
    try {
      scanLedger.recordScan(report, {
        html: rg.toHTML(report),
        markdown: rg.toMarkdown(report),
      });
    } catch (e) { console.error(`[warn] 台账登记失败（不影响报告）：${e.message}`); }
  }

  printReportBrief(report, files, outDir);
  // [D45] --diff-base 给出时，退出码由 diff 门禁裁决（新增才判红），替代 risky 规则
  if (diffInfo) {
    console.log('');
    console.log('  diff 门禁（--diff-base）：');
    console.log(`  基线扫描 : ${diffInfo.baseScanId}`);
    console.log(`  ${diffInfo.diff.summary}`);
    console.log(`  裁决     : exit ${diffInfo.decision.code} —— ${diffInfo.decision.reason}`);
    process.exit(diffInfo.decision.code);
  }
  const risky = report.riskLevel === 'Critical' || report.riskLevel === 'High';
  process.exit(risky ? 2 : 0);
}

main().catch((e) => {
  console.error(`一键扫描失败：${e?.message || e}`);
  if (process.env.DEBUG) console.error(e?.stack || '');
  process.exit(1);
});

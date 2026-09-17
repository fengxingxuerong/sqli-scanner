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
import { cvssFor } from '../server/src/services/reportDelivery.js';
import { VULN_TAXONOMY } from '../server/src/services/vulnTaxonomy.js';
import { parseScope } from '../server/src/core/scopeGuard.js';
// 生效配置的兜底展示值：buildConfig 只在显式传参时写入 level/risk，
// 未传时真实生效的是 defaults（level=1 / risk=2）。若此处凭空补 1，会把「risk=2（含
// time/stacked/oob）」误报成「risk=1」，交付摘要与报告正文自相矛盾——故从同一源头取。
import { defaults as DEFAULT_CONFIG } from '../server/src/config/defaults.js';
import * as scanLedger from '../server/src/services/scanLedger.js';
import { buildConfig } from '../server/bin/cli/config.js';
import { parseArgs, applyRequestFile, resolveTamperPlugins } from '../server/bin/cli/args.js';
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

  const args = parseArgs(rest);
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
  const risky = report.riskLevel === 'Critical' || report.riskLevel === 'High';
  process.exit(risky ? 2 : 0);
}

main().catch((e) => {
  console.error(`一键扫描失败：${e?.message || e}`);
  if (process.env.DEBUG) console.error(e?.stack || '');
  process.exit(1);
});

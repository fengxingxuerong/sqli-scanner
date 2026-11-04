// reportOutput.js —— [D238] 从 bin/cli.js **纯搬移**的报告输出/落盘函数族（逐字搬移，零行为变化）。
// 动机：cli.js 距 1200 行架构软上限仅 25 行余量；09-25 scanRoutes 批沉淀的原则是
// 「接近时主动抽取，不继续往里加」。本族（--format 分发 / --out 落盘 / fix-prompt /
// repro-check / ai-report / 枚举视图）是 cli.js 内聚度最高的可拆块。
// 测试面：formatReport / printExtractView / writeFixPromptsForReport 由 bin/cli.js
// re-export（8+ 测试文件从那里导入，路径不能变——先例见 cli.js 的 args re-export）。
import { mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { ReportGenerator } from '../../src/services/ReportGenerator.js';
import { renderFixPrompts } from '../../src/services/fixPrompt.js';
import { writeAiReport } from '../../src/services/aiReportCli.js';
import { annotateRepro, writeReproPack } from '../../src/services/reproCheck.js';
import * as scanLedger from '../../src/services/scanLedger.js';
import { httpClient } from '../../src/core/httpClient.js';
import { sanitizeForTerminal } from '../../src/core/terminalSafe.js';
import { renderScanSummaryPanel } from './summaryPanel.js';
import { runAlert } from './alert.js';

// [2026-10-12 优化空间勘查 §A3] 两处修：
//   ① 补 db-json（仅拖库数据）——该格式 REST/UI 早有，CLI 与 MCP 的枚举却没有；
//   ② **未知格式从"静默回退 JSON"改为抛错**。旧行为下 `--format db-json` 会写出一个
//      名为 report.db-json 的普通 JSON —— "传了没生效"正是本仓红线（宁可拒绝启动，
//      也不让"以为设了"变成实际没设；与 --config 未知键硬拒同一条政策）。
//   格式集与 REST FORMAT_EXT / MCP get_report enum 同源对齐（parity 有守卫）。
export function formatReport(report, fmt = 'json', opts = {}) {
  // [D243 对标 sqlmap --no-truncate] 取证场景：长 payload / 长响应不截断。
  // 浅拷贝注入（不改调用方对象，终态快照是共享只读视图）。
  if (opts.noTruncate) report = { ...report, _noTruncate: true };
  // [D245 对标 sqlmap --csv-del] 分隔符：单字符，或 `\t` 字面量表示制表符。
  // 非法值静默回落逗号（导出格式不该因为一个分隔符让整份报告写不出来）。
  if (opts.csvDelimiter) {
    const d = opts.csvDelimiter === '\\t' ? '\t' : String(opts.csvDelimiter);
    if (d.length === 1) report = { ...report, _csvDelimiter: d };
  }
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
  if (f === 'db-json') {
    // 仅拖库数据（库/表/列/行）；单源在 ReportGenerator.toDBJSON（ScanManager 共用）
    return new ReportGenerator().toDBJSON(report);
  }
  // JSON 走 ReportGenerator.toJSON：与其它导出格式共用「挂 PoC → target 脱敏 → 点位脱敏」管道，
  // 避免 -o 落盘报告把 target.cookieParams / Cookie 注入点原文写进磁盘。
  if (f === 'json') return new ReportGenerator().toJSON(report);
  throw new Error(
    `--format 未知格式：${fmt}（仅支持 json|csv|markdown|md|html|sarif|db-json）\n` +
    '  旧行为是静默回退 JSON —— 那会让"以为设了 db-json"实际拿到普通 JSON，故改为拒绝。'
  );
}

// 极简参数解析（避免引入 commander 依赖）

/**
 * [D177] 复现检查：重放每条 finding 的 PoC 两次 → 判「已复现 / 单次命中 / 不可重放」，
 * 写进 `vuln.repro` 与 `summary.repro`，并把 repro.sh + expect.json 落盘。
 * 重放走 httpClient（SSRF/scope 护栏照旧生效），失败只影响判定，不中断扫描。
 * @param {object} report 引擎报告（原地挂判定）
 * @param {object} args CLI 参数
 * @returns {Promise<void>}
 */
export async function applyReproCheck(report, args) {
  const repeats = 2;
  // PoC 是**渲染期惰性挂载**的（ReportGenerator.attachPoc 返回新对象）：不先挂上，
  // 每条 finding 都会因为没有 poc.url 被判成 unreplayable（D177 首跑就是这样 0/3 的）。
  const withPoc = new ReportGenerator().attachPoc(report);
  const summary = await annotateRepro(withPoc, {
    request: (o) => httpClient.request({ ...o, proxy: args.proxy || undefined, insecureTls: Boolean(args.insecureTls) }),
    repeats,
    timeoutMs: args.httpTimeoutMs || undefined,
  });
  // 判定写回原报告（attachPoc 是纯函数，不回写入参）
  report.vulns = report.vulns || [];
  report.vulns.forEach((v, i) => { if (withPoc.vulns?.[i]?.repro) v.repro = withPoc.vulns[i].repro; });
  report.summary = report.summary || {};
  report.summary.repro = summary;
  const explicit = typeof args.reproCheck === 'string' && args.reproCheck.trim() ? args.reproCheck : null;
  const dir = explicit ? resolvePath(explicit) : join(fixPromptBaseDir(args), 'repro');
  const { count } = writeReproPack(withPoc, dir, { repeats, target: report?.target?.url });
  console.error(
    `复现检查：已复现 ${summary.reproduced}/${summary.checked}（单次命中 ${summary.singleHit}、不可重放 ${summary.unreplayable}）；` +
      `脚本已写入 ${dir}（${count} 份；一致 ≠ 漏洞仍存在）`
  );
}
/**
 * [D176] 单目标报告落盘（`--out`）：目录语义 / 单文件语义 / 台账快照。
 * 与 `emitSingleScanOutput` 拆开是为了守住函数级复杂度软上限（18 > 15 的教训）。
 * @param {object} report 引擎报告
 * @param {object} args CLI 参数
 * @returns {string} 实际使用的格式
 */
function writeSingleReportFiles(report, args) {
  // [P1-FIX 2026-09-05] 按 --format 分发导出（json|csv|markdown|html），与 REST /report/export 同源
  const fmt = String(args.format || 'json').toLowerCase();
  // [goal 批次 A-3] -o 目录语义：路径是已存在目录或以分隔符结尾 → 写 report.<ext> 组
  //（sqlmap 风格），否则保持单文件兼容。交付默认 --format html 时同时落 md 便于交接。
  const outIsDir = (() => { try { return statSync(args.out).isDirectory(); } catch { return /[\\/]$/.test(args.out); } })();
  if (outIsDir) {
    mkdirSync(args.out, { recursive: true });
    const ext = fmt === 'markdown' || fmt === 'md' ? 'md' : fmt === 'db-json' ? 'db.json' : fmt;
    writeFileSync(join(args.out, `report.${ext}`), formatReport(report, fmt, { noTruncate: args.noTruncate, csvDelimiter: args.csvDelimiter }), 'utf-8');
    if (fmt === 'html') writeFileSync(join(args.out, 'report.md'), formatReport(report, 'markdown', { noTruncate: args.noTruncate, csvDelimiter: args.csvDelimiter }), 'utf-8');
    if (fmt === 'markdown' || fmt === 'md') writeFileSync(join(args.out, 'report.html'), formatReport(report, 'html', { noTruncate: args.noTruncate, csvDelimiter: args.csvDelimiter }), 'utf-8');
  } else {
    writeFileSync(args.out, formatReport(report, fmt, { noTruncate: args.noTruncate, csvDelimiter: args.csvDelimiter }), 'utf-8');
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
  return fmt;
}

/**
 * [D205] 两个 opt-in 产物出口（`--fix-prompt` / `--ai-report`）。
 * 从 `emitSingleScanOutput` 抽出：那里每多一个 if 都算进函数级复杂度门禁，而这两个出口
 * 都是「扫描完成后才跑、失败不影响扫描结论」的同构逻辑，放在一起更清楚。
 * @param {object} report 引擎报告
 * @param {object} args CLI 参数
 * @returns {Promise<void>} 两个出口都跑完（或按未启用跳过）后 resolve
 */
async function writeOptInArtifacts(report, args) {
  // [D176] 修复提示词：命中项 → 改哪/怎么改/改完怎么验。刻意不自动改代码。
  if (args.fixPrompt) {
    const { dir, count } = writeFixPromptsForReport(report, args);
    console.error(`修复提示词已写入 ${dir}（${count} 条；改完按其中命令复测，期望 0 命中）`);
  }
  // [D205] AI 报告：LLM 三模型流水线。失败只判「执行失败」（exitCode=1），
  // **不改**扫描结论与风险等级——AI 不可用不等于没洞，也不等于有洞。
  if (args.aiReport) {
    process.stderr.write('AI 报告：调用网关三模型流水线（analyst→writer→reviewer），通常需 1-3 分钟…\n');
    const r = await writeAiReport(report, args);
    if (r.ok) {
      process.stderr.write(`AI 报告已写入 ${r.file}（${r.model}，${Math.round((r.elapsedMs || 0) / 1000)}s，${r.bytes}B）\n`);
    } else {
      process.stderr.write(`AI 报告失败：${r.error}\n`);
      process.exitCode = 1;
    }
  }
}

/**
 * [D176] 单目标模式的产物落地：报告（`--out` / 枚举视图 / stdout JSON）+ opt-in 产物。
 * 从 `main` 抽出（函数级复杂度门禁盯 main：每加一个出口分支都算增长）。
 * [D205] 改为 async：`--ai-report` 要等 LLM 流水线返回；main 里只多一个 `await ` 前缀，不新增行。
 * @param {object} report 引擎报告
 * @param {object} args CLI 参数
 * @param {{enumActive?: boolean, exploitMode?: boolean}} flags 编排层状态
 * @returns {Promise<void>} 产物写完后 resolve
 */
export async function emitSingleScanOutput(report, args, flags) {
  // [D195] 人读结果面板：枚举/拖库/利用模式有自己的产物形态，不叠面板
  if (!flags?.enumActive && !args.dump && !flags?.exploitMode) {
    process.stderr.write(renderScanSummaryPanel(report) + '\n');
  }
  if (args.out) {
    const fmt = writeSingleReportFiles(report, args);
    // [D195] 默认 json-only 时提示人读格式的获取方式（零行为变更，纯指引）
    const fmtHint = fmt === 'json' ? '；人读格式加 --format markdown' : '';
    console.error(`报告已写入 ${args.out}（格式 ${fmt}${fmtHint}）`);
  } else if (flags?.enumActive || args.dump) {
    // 枚举/拖库模式：默认打印 report.data 精简视图（文本，对标 sqlmap 终端输出）
    printExtractView(report);
  } else if (!flags?.exploitMode) {
    console.log(JSON.stringify(report, null, 2));
  }
  await writeOptInArtifacts(report, args);
  // [D199 对标 sqlmap --alert] 命中联动宿主命令：报告已成形、产物已落盘后才触发，
  // 失败不影响退出码。批量模式（results 摘要形态）不走本函数，边界见 help/README。
  runAlert(report, args);
}

/**
 * [D176] 修复提示词的默认落点：`--out` 是目录（或不存在但以分隔符结尾）就用它，
 * 是文件就用它所在目录；没给 `--out` 用当前目录。都不套 `fix-prompts/`。
 * @param {object} args CLI 参数
 * @returns {string} 绝对目录
 */
function fixPromptBaseDir(args) {
  const out = typeof args?.out === 'string' && args.out.trim() ? args.out : process.cwd();
  try {
    if (statSync(out).isDirectory()) return resolvePath(out);
  } catch {
    if (/[\\/]$/.test(out)) return resolvePath(out);
  }
  return resolvePath(dirname(out));
}

/**
 * [D176] 把报告里的命中项渲染成修复提示词并落盘（索引 + 每条一份）。
 * 目录语义：`--fix-prompt <dir>` 直接写该目录；`--fix-prompt`（不带值）写
 * `<--out 目录或当前目录>/fix-prompts/`。**不自动改代码**。
 * @param {object} report 引擎报告
 * @param {object} args CLI 参数（仅用 `fixPrompt` 与 `out`）
 * @returns {{dir: string, count: number}} 落盘目录与提示词条数
 */
export function writeFixPromptsForReport(report, args) {
  const explicit = typeof args?.fixPrompt === 'string' && args.fixPrompt.trim() ? args.fixPrompt : null;
  const dir = explicit ? resolvePath(explicit) : join(fixPromptBaseDir(args), 'fix-prompts');
  const { index, items } = renderFixPrompts(report, { url: report?.target?.url || report?.url });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'README.md'), index, 'utf-8');
  for (const it of items) writeFileSync(join(dir, it.file), it.content, 'utf-8');
  return { dir, count: items.length };
}
// 枚举模式精简文本输出（report.data 视图）
export function printExtractView(report) {
  // 本视图打印的每一段都是**目标可控**数据（库名/表名/列名/单元格值/凭据），故在出口处统一消毒控制序列：
  // OSC 0 能改写操作员终端标题、OSC 8 能造出"显示文字与真实目标完全不同"的可点击超链接、
  // CR/CSI 能覆盖刚打印的那一行、裸换行能伪造一条时间戳齐全的假日志行。
  // 消毒定义在函数入口、视图内 24 个打印点一律走 out()：这类出口的常态失效方式是"漏一处"，
  // 要求每个调用点都记得套一层等于没设防。
  const out = (...args) => console.log(...args.map((a) => (typeof a === 'string' ? sanitizeForTerminal(a) : a)));
  const data = report.data;
  if (!data) { out('（无提取数据，注入点未确认或提取失败）'); return; }
  if (data.currentDb !== undefined && data.currentDb !== null) out(`current database: ${data.currentDb}`);
  if (data.currentUser !== undefined && data.currentUser !== null) out(`current user: ${data.currentUser}`);
  if (data.users !== undefined && data.users !== null) out(`users: ${data.users}`);
  if (data.passwords !== undefined && data.passwords !== null) out(`passwords: ${data.passwords}`);
  if (data.hostname !== undefined && data.hostname !== null) out(`hostname: ${data.hostname}`);
  if (data.isDba !== undefined && data.isDba !== null) out(`is DBA: ${data.isDba}`);
  if (data.userPrivs !== undefined && data.userPrivs !== null) out(`privileges: ${data.userPrivs}`);
  if (data.roles !== undefined && data.roles !== null) out(`roles: ${data.roles}`);
  const hasTables = data.tables && Object.keys(data.tables).length;
  const hasCols = data.columns && Object.keys(data.columns).length;
  const hasRows = data.rows && Object.values(data.rows).some(v => Array.isArray(v) && v.length);
  const hasModeField = data.currentDb || data.currentUser || data.users || data.passwords || data.hostname || data.isDba || data.userPrivs || data.roles || (data.counts && Object.keys(data.counts).length);
  // --dbs：仅库名列表（其它模式不进入此分支）
  if (!hasTables && !hasCols && !hasRows && !hasModeField) {
    for (const db of (data.databases || [])) out(db);
    if (!data.databases || !data.databases.length) out('（未枚举到数据库）');
  }
  // --tables / --columns / --dump
  for (const [db, tabs] of Object.entries(data.tables || {})) {
    for (const t of tabs) {
      const key = `${db}.${t}`;
      const cols = data.columns ? data.columns[key] : null;
      const rows = data.rows ? data.rows[key] : null;
      if (Array.isArray(rows) && rows.length) {
        const showCols = cols || Object.keys(rows[0]);
        out(`[${key}]  共 ${rows.length} 行`);
        out('  ' + showCols.join(' | '));
        for (const row of rows.slice(0, 50)) {
          out('  ' + showCols.map(c => row[c] == null ? '' : row[c]).join(' | '));
        }
        if (rows.length > 50) out(`  …（仅显示前 50 行，共 ${rows.length} 行）`);
      } else if (cols && cols.length) {
        out(`${key}: ${cols.join(', ')}`);
      } else {
        out(key);
      }
    }
  }
  // --count
  if (data.counts) {
    for (const [k, v] of Object.entries(data.counts)) out(`${k}: ${v == null ? 'N/A' : v} 行`);
  }
  // --search：输出匹配的表名和列名汇总
  if (data.search) {
    out(`search keyword: ${data.search.keyword}`);
    if (data.search.matchedTables && data.search.matchedTables.length) {
      out(`matched tables: ${data.search.matchedTables.join(', ')}`);
    } else {
      out('matched tables: (none)');
    }
    if (data.search.matchedColumns && data.search.matchedColumns.length) {
      for (const m of data.search.matchedColumns) {
        out(`  ${m.table}: ${m.columns.join(', ')}`);
      }
    }
  }
  // --schema：输出表结构定义
  if (data.schemas && Object.keys(data.schemas).length) {
    out('schemas:');
    for (const [k, v] of Object.entries(data.schemas)) {
      out(`  ${k}: ${v == null ? '(null)' : v}`);
    }
  }
}

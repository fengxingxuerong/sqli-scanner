// ============================================================================
// cli/summaryPanel.js —— [D195] 单目标扫描收场的人读结果面板
//
// 报告里的结论/覆盖缺口/未验证面此前只有 json 形态（机器可读），终端用户只看到
// 「[完成] 风险等级 Low」——检出没有、下一步做什么都得自己翻报告。本模块只做
// **既有披露的终端呈现**，不产生新检测结论。
// 从 bin/cli.js 拆出（pre-commit 体积门禁：cli.js >1200 行即红）。
// ============================================================================

/** [D195] 耗时（finishedAt-startedAt 可读化；缺失降级 '-'）。 */
function panelDuration(report) {
  if (!(report.finishedAt && report.startedAt)) return '-';
  const ms = Math.max(0, Date.parse(report.finishedAt) - Date.parse(report.startedAt));
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

/** [D195] 已测注入面标注（≤3 全列，否则前 3 折叠）。 */
function panelTestedLabel(points) {
  const label = (p) => `${p.param}@${p.location || p.in || '?'}`;
  if (points.length <= 3) return points.map(label).join('、') || '无';
  return `${points.slice(0, 3).map(label).join('、')} 等 ${points.length} 个`;
}

/** [D195] 结论行（verdict + 风险等级）。 */
function panelVerdictLine(report, s) {
  const risk = report.riskLevel ?? s.riskLevel;
  return `结论      ${s.verdict || 'unknown'}${risk ? ` · 风险 ${risk}` : ''}`;
}

/** [D195] 覆盖缺口块（未测注入面 + 前 2 条提示，其余折叠指报告）。空数组返回 []。 */
function panelCoverageLines(uncovered) {
  if (!uncovered.length) return [];
  const lines = [`覆盖缺口  ${uncovered.length} 类注入面未测：${uncovered.map((u) => u.label || u.surface).join('、')}`];
  for (const u of uncovered.slice(0, 2)) lines.push(`          · ${u.surface}：${u.hint || ''}`);
  if (uncovered.length > 2) lines.push(`          （其余 ${uncovered.length - 2} 项及完整提示见报告 uncoveredSurfaces）`);
  return lines;
}

/** [D195] 下一步建议（按报告事实推导：命中→复测/修复提示词；缺口→扩覆盖；inconclusive→先处置会话）。 */
function panelNextSteps(vulnCount, uncovered, verdict) {
  const next = [];
  if (vulnCount > 0) next.push('命中项复核：--repro-check（PoC 重放判定）｜修复提示词：--fix-prompt');
  if (uncovered.length > 0) next.push(`扩覆盖复扫：--level 2+（cookie/header 面）或 --test-path/--forms（${uncovered[0]?.surface || ''} 等）`);
  if (/inconclusive|session_expired/.test(verdict)) next.push('会话/签名问题需先处置（见结论行），否则阴性结论不可信');
  return next.length ? `下一步    ${next.join('｜')}` : null;
}

/**
 * [D195] 单目标扫描收场的人读结果面板。
 * @param {object} report 引擎报告（target/points/vulns/summary）
 * @returns {string} 多行面板文本（不含尾随换行；调用方决定输出流）
 */
export function renderScanSummaryPanel(report) {
  const s = report.summary || {};
  const t = report.target || {};
  const vulns = report.vulns || [];
  const points = report.points || [];
  const uncovered = s.uncoveredSurfaces || [];
  const unverified = s.unverifiedSurfaces || [];

  const lines = [];
  lines.push('─── 扫描结果 ' + '─'.repeat(43));
  if (t.baseUrl) lines.push(`目标      ${t.method || 'GET'} ${t.baseUrl}`);
  lines.push(panelVerdictLine(report, s));
  if (s.verdictNote) lines.push(`          ${String(s.verdictNote).slice(0, 120)}`);
  lines.push(`命中      ${vulns.length} 漏洞｜已测注入面 ${points.length} 个（${panelTestedLabel(points)}）`);
  lines.push(...panelCoverageLines(uncovered));
  if (unverified.length) {
    lines.push(`未验证面  ${unverified.length} 类注入面未完成有效检测（被拦/网络失败）——「未检出」不等于「测过没洞」`);
  }
  lines.push(`耗时      ${panelDuration(report)}`);
  const nextLine = panelNextSteps(vulns.length, uncovered, s.verdict || 'unknown');
  if (nextLine) lines.push(nextLine);
  lines.push('─'.repeat(52));
  return lines.join('\n');
}

/** [D196] 批量落盘指引：默认 json-only 时提示人读格式（纯提示，零行为变更）。 */
export function batchWriteHint(fmt) {
  return fmt === 'json' ? '；人读格式加 --format markdown' : '';
}

/** [D196] 批量命中目标点名（High/Critical 逐个 URL + 漏洞数；无命中返回 []）。 */
export function batchHitLines(results, urlOf) {
  const hits = (results || []).filter((r) => r.riskLevel === 'High' || r.riskLevel === 'Critical');
  if (!hits.length) return [];
  const lines = [`命中目标  ${hits.length} 个（High/Critical）:`];
  for (const h of hits) lines.push(`          - ${urlOf(h.url)}：${h.riskLevel} · ${h.vulns} 漏洞`);
  return lines;
}

/** [D196] 批量下一步建议（按批量摘要事实推导）。 */
export function batchNextLine(summary) {
  const s = summary || {};
  const next = [];
  if (s.hasHigh) next.push('命中项复核：--repro-check ｜ 修复提示词：--fix-prompt');
  if (s.needsReview > 0) next.push('需复核目标先处置（0 注入点 ≠ 测过）');
  if (s.failed > 0) next.push('失败目标核查可达性后重扫');
  return next.length ? `下一步    ${next.join('｜')}` : null;
}

/** [D196] -l 日志批量条目的可读名（请求对象取 .url 字段）。导出以让 main 零分支复用。 */
export const urlOfLogRequest = (u) => (u?.url || u);

/**
 * [D196] 批量收场附加行：命中目标点名 + 下一步（主流程零新增分支，一行调用）。
 * ⚠ 与 batchPool.runBatch 同款约定：p 参数不设 `= {}` 缺省（TS2739 会按解构必填字段报错）。
 * @param {object} p
 * @param {Array<{riskLevel?:string, vulns?:number, url:any}>} p.results
 * @param {(url:any)=>string} p.urlOf
 * @param {object} p.summary summarizeBatch 的产物
 * @param {(msg:string)=>void} [p.log] 输出函数（默认 console.error）
 */
export function printBatchHitsAndNext(p) {
  const out = typeof p.log === 'function' ? p.log : console.error;
  for (const l of batchHitLines(p.results, p.urlOf)) out(l);
  const nl = batchNextLine(p.summary);
  if (nl) out(nl);
}

/**
 * [D196] 批量收场摘要整块（-m/-l 两条路径共用）：汇总+风险分布+耗时、命中目标点名、
 * 失败目标点名、需复核对点名、下一步。**只做既有事实的终端呈现**，点名语义与
 * batchPool.runBatch 的注释口径一致（failures=编排异常，needsReview=结论不可信）。
 * @param {object} p
 * @param {string} p.title 完成行标题（「批量扫描完成」/「日志批量扫描完成」）
 * @param {object} p.summary summarizeBatch 的产物
 * @param {Array<{riskLevel?:string, vulns?:number, url:any}>} p.results
 * @param {(url:any)=>string} p.urlOf
 * @param {Array<{url:any, message:string}>} p.failures
 * @param {Array<{url:any, why:string}>} [p.needsReview] -l 路径无 audit 时不传
 * @param {number} p.startedAt Date.now() 起点（耗时）
 * @param {(msg:string)=>void} [p.log]
 */
export function printBatchSummary(p) {
  const out = typeof p.log === 'function' ? p.log : console.error;
  const s = p.summary || {};
  const dur = `${((Date.now() - p.startedAt) / 1000).toFixed(1)}s`;
  out(`\n${p.title}：${s.ok} 个成功 / ${s.failed} 个失败${s.needsReview != null ? ` / ${s.needsReview} 个需复核` : ''}（共 ${s.total}）· 耗时 ${dur}`);
  out(`  风险分布: ${Object.entries(s.byRisk || {}).map(([k, v]) => `${k}=${v}`).join(' ') || '(无)'}`);
  for (const l of batchHitLines(p.results, p.urlOf)) out(l);
  // 失败目标必须**点名**：只报一个数字等于把"哪个目标没扫"变成悬案
  for (const f of p.failures || []) out(`  失败目标:\n    - ${p.urlOf(f.url)}：${String(f.message).slice(0, 200)}`);
  // 「需复核」= 报告产出了但结论不可信（典型：目标不通 ⇒ 0 注入点 ⇒ 一个请求都没发）。
  const needsReview = p.needsReview || [];
  if (needsReview.length) {
    out('  需复核（扫完了但可能什么都没测，结论不可作为无漏洞依据）:');
    for (const n of needsReview) out(`    - ${p.urlOf(n.url)}：${n.why}`);
  }
  const nl = batchNextLine(s);
  if (nl) out(nl);
}

export default { renderScanSummaryPanel, batchWriteHint, batchHitLines, batchNextLine, printBatchHitsAndNext, printBatchSummary, urlOfLogRequest };

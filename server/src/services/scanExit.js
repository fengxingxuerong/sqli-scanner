// ============================================================================
// scanExit.js —— 单目标扫描退出码的**唯一真源**（[D253] 2026-11-05）
//
// 起因（外部裁判靶场实测，证据 docs/cli-compat-external-labs-2026-11-05.txt）：
//   `--param-filter=path` 把注入点删光时，引擎日志打 `[错误]`，报告却是 0 洞，
//   cli.js 与 one-click-scan.mjs **都 exit 0** —— CI 把「参数配置错误」判成「没漏洞」。
//   AGENTS.md §1.1 早已写明「筛选把点位删光时报错退出」，实现没跟上。
//
// 契约：执行失败 = 1（不是「未检出」）；Critical/High = 2；其余 = 0。
// 两条 CLI 入口必须都走这里，避免「修了一条、另一条继续假绿」。
// ============================================================================

/**
 * 取本次扫描的执行失败原因（供入口打印可读提示）。
 * @param {object} report 扫描报告
 * @returns {string|null} 失败原因；无失败时 null
 */
export function scanExecutionError(report) {
  const e = report?.summary?.executionError;
  if (!e) return null;
  return typeof e === 'string' ? e : String(e.message || e.code || '扫描执行失败');
}

/**
 * 单目标扫描的退出码。执行失败优先于风险等级——错误报告里 riskLevel 通常是 Low，
 * 若先按风险判码就会退回 0，这正是本次要堵的假绿。
 * @param {object} report 扫描报告
 * @returns {0|1|2} 0 未发现高危 / 1 执行失败 / 2 发现 Critical 或 High
 */
export function scanExitCode(report) {
  if (scanExecutionError(report)) return 1;
  const risk = report?.riskLevel;
  return risk === 'Critical' || risk === 'High' ? 2 : 0;
}

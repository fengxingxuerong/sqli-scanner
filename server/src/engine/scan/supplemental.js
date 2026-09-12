// ============================================================================
// scan/supplemental.js —— 补充检测趟（原 scanRunner.runScanLoop 阶段 3.5 / 3.6）
//
// 从 1148 行的 runScanLoop 中搬出（2026-09-12 拆分第一批）。**纯搬移，行为不变**。
//
// 两趟都是 opt-in、独立实例、命中并入同一 finalVulns 通道，对一阶检测零侵入：
//   3.5 二阶注入（Stored/2nd-order）—— 门控 secondOrder.enabled
//   3.6 非 SQL 注入（NoSQL/GraphQL/SSTI）—— 门控 noSql.enabled
// 且目标已判不可达（validity.shouldAbort）时**都不发起**：
// 对着死目标跑补充趟只会堆叠无效阴性结果。
// ============================================================================

/**
 * @param {object} run 扫描运行期上下文（见 scanRunner.js）
 * @returns {Promise<void>}
 */
export async function supplementalPasses(run) {
  const { sm, scanId, target, points, dbms, validity, finalVulns } = run;

  // 3.5) 二阶补充趟：在一阶聚合之后运行，并入同一 finalVulns（门控 + 独立实例，对一阶零侵入）
  const soVulns = validity.shouldAbort ? [] : await sm._runSecondOrder(scanId, target, points, dbms);
  for (const v of soVulns) finalVulns.push(v);

  // 3.6) 非 SQL 注入补充趟（NoSQL/GraphQL/SSTI）：门控 noSql.enabled 才跑，对无此类后端的
  // 目标默认关闭以避免噪音；命中并入同一 finalVulns（与二阶同通道，opt-in 独立趟）。
  const noSqlVulns = validity.shouldAbort ? [] : await sm._runNoSql(scanId, target, points, dbms);
  for (const v of noSqlVulns) finalVulns.push(v);
}

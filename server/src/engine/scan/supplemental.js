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

import { _runOobBackground } from './supplementalRuns.js';

/**
 * @param {object} run 扫描运行期上下文（见 scanRunner.js）
 * @returns {Promise<void>}
 */
export async function supplementalPasses(run) {
  const { sm, scanId, target, points, dbms, validity, finalVulns, fullyTestedPoints, guard, report } = run;

  // 3.5) 二阶补充趟：在一阶聚合之后运行，并入同一 finalVulns（门控 + 独立实例，对一阶零侵入）
  const soVulns = validity.shouldAbort ? [] : await sm._runSecondOrder(scanId, target, points, dbms);
  for (const v of soVulns) finalVulns.push(v);

  // 3.6) 非 SQL 注入补充趟（NoSQL/GraphQL/SSTI）：门控 noSql.enabled 才跑，对无此类后端的
  // 目标默认关闭以避免噪音；命中并入同一 finalVulns（与二阶同通道，opt-in 独立趟）。
  const noSqlVulns = validity.shouldAbort ? [] : await sm._runNoSql(scanId, target, points, dbms);
  for (const v of noSqlVulns) finalVulns.push(v);

  // 3.7) 背景 OOB 哨兵（[D108]，对标 Collaborator Everywhere）：门控 oob.background.enabled。
  // 补的是「选定技术不覆盖的面」——risk=1 剔除 oob、被预筛选/静态判定跳过的点、未生成
  // 注入点的请求头。命中并入同一 finalVulns（technique='oob'，与一阶同通道）。
  // 直接调用导出的包装层（不挂 ScanManager.prototype）：挂载会拉长原型挂载尾部，
  // 与 httpClient/Detector/Exploiter 的挂载行产生 29 个新克隆窗口（duplication 只减不增）。
  const bgVulns = validity.shouldAbort
    ? []
    : await _runOobBackground.call(sm, scanId, target, points, dbms, fullyTestedPoints, guard, report);
  for (const v of bgVulns) finalVulns.push(v);
}

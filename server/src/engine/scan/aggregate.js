// ============================================================================
// scan/aggregate.js —— 漏洞聚合 + 去重（原 scanRunner.runScanLoop 阶段 3）
//
// 从 runScanLoop 中搬出（2026-09-12 拆分第二批）。**纯搬移，行为不变**。
//
// 语义：把「逐点逐技术的原始命中」聚合为最终漏洞列表。
// 同点出现 stacked 命中时只保留 1 条 stacked(Critical)，其余降级为印证记录（corroborations）——
// 避免同一注入点因为堆叠通道额外命中而被重复计为多个漏洞，虚高风险等级。
//
// 注意：紧随其后的 `if (s.cancelled) { …收尾…; return; }` **没有**一起搬出：
// 它含早退 return，属于主流程控制而非聚合逻辑，留在 runScanLoop 中。
// ============================================================================
import * as eventBus from '../../core/eventBus.js';
import { createVulnerability } from '../models.js';

/**
 * @param {object} run 扫描运行期上下文
 * @returns {{finalVulns: Array, corroborations: Array}}
 */
export function aggregateVulns(run) {
  const { sm, scanId, foundByPoint } = run;

  // 3) 聚合 + 去重（同点 stacked 命中 → 仅留 1 条 stacked(Critical)，其余移入印证）
  const finalVulns = [];
  const corroborations = [];
  for (const { point, found } of foundByPoint.values()) {
    const stackedItem = found.find((f) => f.technique === 'stacked');
    const items = stackedItem ? [stackedItem] : found;
    if (stackedItem) {
      for (const f of found) {
        if (f !== stackedItem) {
          corroborations.push({ pointId: point.id, technique: f.technique, dbms: f.result.dbms });
        }
      }
    }
    for (const f of items) {
      const risk =
        f.technique === 'stacked'
          ? 'Critical'
          : sm.reportGen.riskOf([
              createVulnerability(point.id, f.technique, 'Medium', f.result.payloads, f.result.evidence, f.result.trace),
            ]);
      const vuln = createVulnerability(point.id, f.technique, risk, f.result.payloads, f.result.evidence, f.result.trace);
      vuln.dbms = f.result.dbms;
      // [G4 对标 sqlmap --parse-errors] 透传错误详情（opt-in）：错误原文/上下文/SQL 片段
      if (f.result.errorDetail) vuln.errorDetail = f.result.errorDetail;
      finalVulns.push(vuln);
      eventBus.emit(scanId, 'detection_found', { ...f.result, riskLevel: risk });
    }
  }

  return { finalVulns, corroborations };
}

// ============================================================================
// scan/auditPhase.js —— 只读安全配置审计阶段（D181，对标 sqlmap --audit）
//
// 为什么单独一个阶段：审计问的是「这个库自身有多松」，与「有没有注入」是两回事。
// 混进检测阶段会让两件事的失败互相污染（审计查不到 ≠ 没扫到洞）。
//
// 触发条件（三者同时满足）：`target.config.audit === true`、直连模式（`target.mode==='direct'`）、
// 连接器暴露 `getDriverForAudit()`。任何一条不满足都只写一句 `unknown` 说明原因——
// **绝不静默跳过**（否则读者会以为「审计过了，没问题」）。
// ============================================================================
import { runAudit, auditSentence } from '../audit.js';
import { logger } from '../../core/logger.js';

/**
 * 执行审计并写进报告（`report.audit` + `report.summary.audit`）。
 * @param {object} run 扫描运行期上下文（用 `rawClient` / `target` / `report`）
 * @returns {Promise<void>}
 */
export async function auditPhase(run) {
  const { rawClient, target, report } = run;
  const cfg = (target && target.config) || {};
  if (!cfg.audit) return;

  const notRun = (reason) => {
    report.summary = report.summary || {};
    report.audit = { ran: false, reason, findings: [], summary: { total: 0, pass: 0, fail: 0, unknown: 0 } };
    report.summary.audit = { ran: false, reason, sentence: `未执行安全配置审计：${reason}` };
  };

  if (!target || target.mode !== 'direct') {
    return notRun('需要直连模式（-d <连接串>）才能做配置审计；HTTP 目标无从查询数据库自身配置');
  }
  if (!rawClient || typeof rawClient.getDriverForAudit !== 'function') {
    return notRun('当前连接器不提供只读驱动句柄');
  }

  try {
    const driver = await rawClient.getDriverForAudit();
    const result = await runAudit(driver, { dialect: driver?.dialect });
    report.summary = report.summary || {};
    report.audit = { ran: true, dialect: result.dialect, findings: result.findings, summary: result.summary };
    report.summary.audit = {
      ran: true,
      dialect: result.dialect,
      summary: result.summary,
      sentence: auditSentence(result),
    };
  } catch (e) {
    // 连驱动都拿不到：如实记 unknown，不影响扫描结论
    logger.warn(`[audit] 安全配置审计未完成：${e && e.message}`);
    notRun(`审计执行失败：${String(e?.message || e).slice(0, 160)}`);
  }
}

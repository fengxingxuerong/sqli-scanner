// ============================================================================
// scan/extract.js —— 数据提取趟（原 scanRunner.runScanLoop 阶段 4）
//
// 从 runScanLoop 中搬出（2026-09-12 拆分第二批）。**纯搬移，行为不变**。
//
// 只对「最终保留的漏洞」提取：
//   union/error → 拖库（_extract → dumpAllDatabases），空结果未确认的表进报告约束区
//   boolean    → 二分提取版本证明
//   time       → 时间盲注独立通道（无标量延迟原语时降级布尔）
//   inline     → 内联查询提取（无回显点时返回 null，由其它技术覆盖）
// 点间并行受 extractConcurrency 约束；实际发包速率仍由 HttpClient 令牌桶 + Scheduler 统一限速。
// ============================================================================
import * as eventBus from '../../core/eventBus.js';
import { defaults } from '../../config/defaults.js';

/**
 * @param {object} run 扫描运行期上下文
 * @returns {Promise<void>}
 */
export async function extractPhase(run) {
  const { sm, scanId, s, target, foundByPoint, finalVulns, extracted, report } = run;

  // 4) 提取：仅对最终保留的漏洞做（union/error 拖库；boolean/time 版本证明）。
  // 点间并行（T3）：不同注入点的提取任务并发执行，并行度受 extractConcurrency 约束；
  // 实际发包速率仍被 HttpClient 令牌桶 + Scheduler 统一限速，不放大对目标压力到危险程度。
  const extractTasks = [];
  for (const { point, ctx } of foundByPoint.values()) {
    const vuln = finalVulns.find((v) => v.pointId === point.id);
    if (!vuln) continue;
    extractTasks.push({ point, ctx, vuln });
  }
  if (target.config.enableExtract) {
    const extractConcurrency = Math.max(1, target.config.extractConcurrency || defaults.extractConcurrency);
    await sm._mapPool(extractTasks, async ({ point, ctx, vuln }) => {
      // [MERGED: engine ★FIX-1] 兜底：提取期间用户 stop()，立即停止剩余提取请求
      if (s.cancelled) return;
      if (vuln.technique === 'union' || vuln.technique === 'error') {
        eventBus.emit(scanId, 'scan_phase', { phase: 'extracting', message: `正在从 ${point.dbms || '数据库'} 提取数据…` });
        const exData = await sm._extract(scanId, ctx);
        sm._mergeExtracted(extracted, exData);
        // [P0 2026-09-09] 「0 行未确认」表进报告首屏约束区：空结果 ≠ 空表，
        // 提取通路可能被 WAF/类型限制拦死——交付前必须让使用者看见
        if (exData?.meta?.dumpUnconfirmed?.length) {
          try {
            report.summary = report.summary || {};
            report.summary.constraints = report.summary.constraints || [];
            report.summary.constraints.push(
              `拖库空结果未确认（非空表但提取 0 行，提取通路可能不稳）：${exData.meta.dumpUnconfirmed.join('、')} —— 请人工复核`
            );
          } catch { /* 约束标注失败不影响扫描 */ }
        }
      } else if (vuln.technique === 'boolean') {
        const proof = await sm.extractor.extractProof(ctx);
        // [B-FIX 2026-09-20] 盲注提取「没拿到值」有两种截然不同的原因，必须分开说：
        //   ① 根本没洞 / 判据判 false（正常，无需解释）；
        //   ② **长度二分顶到上界且判据不可区分**（ctx.blindLenCapped）—— 判据失效，
        //      我们主动放弃了这个字段（不再拿上界当长度去逐字节提取）。
        // ② 必须在报告里可见：否则「什么都没提取到」会被读成「目标没数据」。
        if (!proof && ctx?.blindLenCapped) {
          try {
            report.summary = report.summary || {};
            report.summary.constraints = report.summary.constraints || [];
            report.summary.constraints.push(
              `盲注长度探测失败：二分顶到上界 ${ctx.blindLenCappedAt ?? 255} 且响应差异不可区分`
              + `（判据失效，已放弃该字段而非按上界提取）—— ${point.dbms || '未知库'} 的提取结果不完整，请人工复核`
            );
          } catch { /* 约束标注失败不影响扫描 */ }
        }
        if (proof) {
          eventBus.emit(scanId, 'extraction_progress', {
            db: point.dbms,
            table: null,
            count: 1,
            // P2-P7：完整值投票复验未通过时注明低置信（提取值仍可用，需人工复核）
            confidence: ctx.extractConfidence === 'low' ? 'low' : 'high',
            note: `盲注二分提取版本：${proof}${ctx.extractConfidence === 'low' ? '（低置信：完整值复验未通过）' : ''}`,
          });
        }
      } else if (vuln.technique === 'time') {
        // 时间盲注独立提取通道：优先走时间判定，无标量延迟原语的库降级布尔通道。
        // 可选链调用保证老 extractor 桩（仅实现 extractProof）零回归。
        const proof =
          (typeof sm.extractor.extractTimeProof === 'function'
            ? await sm.extractor.extractTimeProof(ctx)
            : null) || (await sm.extractor.extractProof(ctx));
        if (proof) {
          eventBus.emit(scanId, 'extraction_progress', {
            db: point.dbms,
            table: null,
            count: 1,
            confidence: ctx.extractConfidence === 'low' ? 'low' : 'high',
            note: `时间盲注提取版本：${proof}${ctx.extractConfidence === 'low' ? '（低置信：完整值复验未通过）' : ''}`,
          });
        }
      } else if (vuln.technique === 'inline') {
        // 内联提取（对标 sqlmap Q）：把标量子查询注入值位置，期待回显点把结果带出。
        // 无回显点时 extractInlineProof 返回 null（本工具不重建查询模板，故回退到盲注通道由其它技术覆盖）。
        const proof = await sm.extractor.extractInlineProof(ctx);
        if (proof) {
          eventBus.emit(scanId, 'extraction_progress', {
            db: point.dbms,
            table: null,
            count: 1,
            note: `内联查询提取版本：${proof}`,
          });
        }
      }
    }, extractConcurrency);
  }
}

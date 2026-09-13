// ============================================================================
// scan/finalize.js —— 扫描收尾：汇总报告并定级（原 scanRunner.runScanLoop 阶段 5）
//
// 从 1148 行的 runScanLoop 中搬出（2026-09-12 拆分第一批）。**纯搬移，行为不变**：
// 代码逐行等价，只是把闭包变量改成从 run 上下文解构。搬移时未做任何逻辑改动——
// 若需修改行为，请单独提交（否则报告 diff 的行为等价性验证会失去意义）。
//
// 职责：漏洞汇总 → 报告字段与 summary 标注 → 守卫状态落盘 → 会话 finalize → 收尾事件。
// ============================================================================
import * as eventBus from '../../core/eventBus.js';
import { logger } from '../../core/logger.js';
import { createVulnerability } from '../models.js';
import { summarizeSkipped } from '../scanHelpers.js';
import { dbmsEvidenceOf } from '../dbmsEvidence.js';
import { publicReport } from '../scanHelpers.js';

/**
 * @param {object} run 扫描运行期上下文（见 scanRunner.js）
 * @returns {Promise<void>}
 */
export async function finalizeReport(run) {
  const {
    sm, scanId, s, target, report, finalVulns, extracted, restored, session,
    points, pointsToScan, fullyTestedPoints, stackedSelected, corroborations,
    oobUnavailable, dbms, guard, wafAgg, blockPolicy, blockAdaptiveInfo, validity, ctxBase,
  } = run;

  report.vulns = finalVulns;
  // resume 模式：合并历史会话已落盘的命中（已完成点本次被跳过不重测，但结论须保留在报告中）
  if (restored) {
    for (const v of restored.vulns) {
      if (!report.vulns.some((x) => x.pointId === v.pointId && x.technique === v.technique)) {
        report.vulns.push(createVulnerability(v.pointId, v.technique, 'Medium', [], `[resume] 历史会话命中`, null));
      }
    }
  }
  report.data = target.config.enableExtract ? extracted : null;
  // [P0-FIX] resume 模式：合并历史会话已落盘的提取数据（拖库断点续跑不丢已拉数据）。
  // 已完成点本次跳过不重提取，但历史库/表/列/行结论须合并回报告，保证数据证据链完整。
  if (restored && restored.extracted) {
    report.data = sm._mergeExtractedForResume(report.data, restored.extracted);
  }
  // [P0-FIX] 增量落盘：提取数据写入会话（供下次 resume 合并），落盘失败不阻断主流程
  if (session) {
    try { session.extracted = report.data; await session.setExtracted(report.data); } catch { /* 落盘失败不阻断 */ }
  }
  report.summary.stackedEnabled = stackedSelected;
  report.summary.stackedCorroborations = corroborations;
  // [P1 2026-09-09] 跳过点汇总进报告摘要：点级 skipReason 已有（prefilter/static/input_validation），
  // 但汇总层看不到比例——交付报告必须回答「有多少点没测、为什么没测」，否则「没测」像「测了且无漏洞」。
  try {
    const skipped = summarizeSkipped(points);
    if (skipped) {
      report.summary = report.summary || {};
      report.summary.skippedPoints = skipped;
    }
  } catch { /* 汇总失败不影响扫描 */ }
  // [P1 2026-09-09] OOB 不可用标注：oob 被选中但接收端启动失败时，报告必须显式说明
  // （否则 time/oob 场景的「无带外」会被误读成「无漏洞」）
  if (oobUnavailable) {
    report.summary = report.summary || {};
    report.summary.oobUnavailable = { reason: oobUnavailable };
  }
  const hasData = sm._hasData(extracted);
  report.riskLevel = hasData ? 'Critical' : sm.reportGen.riskOf(finalVulns);
  report.dbms = dbms;
  report.finishedAt = new Date().toISOString();
  // [熔断] 目标库健康状态落报告：扫出问题时必须让使用者看见「目标可能已被影响」
  const health = guard.summary();
  if (health) {
    report.dbHealth = health;
    report.summary = report.summary || {};
    report.summary.dbHealth = health;
    // 单注入点扫描不会进入「下一注入点」分支，abort 事件在收尾处补发，
    // 保证前端/调用方一定能收到中止通知
    if (health.aborted && !guard._abortLogged) {
      guard._abortLogged = true;
      logger.error(`[db-guard] 目标数据库连续报致命错误 ${guard.fatalHits} 次，扫描结果不可信（基线已污染）`);
      eventBus.emit(scanId, 'db_health_abort', { fatalId: health.fatalId, fatalHits: guard.fatalHits });
    }
  }
  // [P0-FIX 2026-09-08] 扫描结论可信度落报告（report.validity / report.summary.validity）
  // 并裁定阴性结论 verdict；status!=='ok' 时额外 emit scan_validity（前端 Banner / 428 门控消费）
  run.applyValidity(report, { points: pointsToScan, done: fullyTestedPoints });
  // WAF 规避标注：任一规避开关开启时，在报告摘要中记录（便于结果复现）
  const we = target.config && target.config.wafEvasion;
  if (we && (we.randomUA || we.jitterMs > 0 || we.obfuscate || (we.tamper && we.tamper.enabled))) {
    report.summary = report.summary || {};
    report.summary.wafEvasion = {
      randomUA: !!we.randomUA,
      jitterMs: Number(we.jitterMs) || 0,
      obfuscate: !!we.obfuscate,
      // tamper 链式组合标注（enabled/plugins 有序/intensity 仅审计）
      tamper: {
        enabled: !!(we.tamper && we.tamper.enabled),
        plugins: Array.isArray(we.tamper && we.tamper.plugins) ? [...we.tamper.plugins] : [],
        intensity: (we.tamper && we.tamper.intensity) || 'medium',
      },
    };
  }
  // WAF 指纹识别汇总：识别到 WAF 时发射 waf_detected 事件并在报告中记录（零额外发包）
  const wafVendors = [...wafAgg.values()].sort((a, b) => b.confidence - a.confidence);
  if (wafVendors.length > 0) {
    const suggestions = sm.wafRecommend(wafVendors);
    eventBus.emit(scanId, 'waf_detected', { vendors: wafVendors, suggestions });
    report.summary = report.summary || {};
    report.summary.wafDetected = wafVendors;
  }
  // [P1-FIX 2026-09-10] 方言验证等级落盘：把「这个数据库我验证到什么程度」写进报告本体，
  // 交付时客户/复核人能自行判断结论可信度，而不是只存在于 README（实测发现报告层完全没有该声明）。
  // 取值按各点识别出的 dbms 汇总（多点可能识别出不同库，保守取最低等级）。
  report.summary = report.summary || {};
  try {
    const levels = pointsToScan
      .map((p) => dbmsEvidenceOf(p.dbms))
      .filter((e) => e.dbms);
    if (levels.length) {
      const rank = { verified: 2, partial: 1, 'template-only': 0 };
      const worst = levels.reduce((a, b) => (rank[b.level] < rank[a.level] ? b : a), levels[0]);
      report.summary.dbmsEvidence = {
        dbms: worst.dbms,
        level: worst.level,
        levelText: worst.levelText,
        evidence: worst.evidence,
        caveat: worst.caveat,
        all: [...new Set(levels.map((e) => `${e.dbms}:${e.level}`))],
      };
    }
  } catch (e) {
    logger.warn(`方言验证等级写入失败（不影响报告主体）：${e.message}`);
  }
  // [P0-FIX 2026-09-10] 拦截处置策略落盘：前端/报告要能说清「本次被压制了什么、用了什么链重跑」
  report.summary.blockPolicy = {
    action: blockPolicy?.action ?? 'none',
    reason: blockPolicy?.reason ?? null,
    tamperHint: Array.isArray(blockPolicy?.tamperHint) ? [...blockPolicy.tamperHint] : [],
    backoffMs: blockPolicy?.backoffMs ?? null,
  };
  // [P0-FIX 2026-09-12] 报告一致性：blockPolicy 由 decideBlockPolicy 依「厂商识别 + wafEvasion 配置」
  // 生成，不看本次实际发生的拦截与自适应重跑，于是会出现自相矛盾的交付物——实测 waf 场景报告里
  // blockPolicy.action='none'（理由「无拦截证据」），而 summary.wafAdaptive.triggered=true、
  // validity.status='blocked'（拦截 8 次），PoC 里的 payload 已经是自适应换链后的 `1 && 1=1`。
  // 客户只读 blockPolicy 会误判「目标没有 WAF 拦截」。此处用实际证据校正，保持单一事实来源。
  if (blockAdaptiveInfo?.triggered && report.summary.blockPolicy.action === 'none') {
    report.summary.blockPolicy = {
      action: blockAdaptiveInfo.mode === 'filterBypass' ? 'filterBypass' : 'adaptiveTamper',
      reason:
        `本次实际出现拦截响应（blockHits=${blockAdaptiveInfo.blockHits ?? blockAdaptiveInfo.errorOnlyPoints ?? '?'}）` +
        `并已自动换链重跑：${JSON.stringify(blockAdaptiveInfo.chains?.[0] || [])}`,
      tamperHint: Array.isArray(blockAdaptiveInfo.chains?.[0]) ? [...blockAdaptiveInfo.chains[0]] : [],
      backoffMs: report.summary.blockPolicy.backoffMs,
    };
  }
  if (blockAdaptiveInfo) report.summary.wafAdaptive = blockAdaptiveInfo;
  // 有效性守卫已判 blocked（拦截占比超阈值）时，同样不得对外声称「无拦截证据」
  const valStatus = (validity && typeof validity.summary === 'function' ? validity.summary() : null)?.status;
  if (valStatus === 'blocked' && report.summary.blockPolicy.action === 'none') {
    report.summary.blockPolicy.action = 'none_but_blocked';
    report.summary.blockPolicy.reason =
      '本次请求被大量拦截（validity.status=blocked），未执行自适应重跑（可能无未命中点可补）；结论可信度受抑制，详见 summary.validity';
  }
  // 会话落盘收尾（resume 模式可用同一 sessionFile 续跑/复核）：必须先 finalize 落盘完成，再置 completed，
  // 避免 resume 端在 status=completed 后、落盘前抢读到一个 vulns 为空的半成品会话。
  if (session) await session.finalize(report).catch(() => {});
  s.status = 'completed';
  // [MERGED: security] scan_completed 事件脱敏：SSE 不再携带 target 凭据
  eventBus.emit(scanId, 'scan_completed', publicReport(report));
  await sm._maybeClose(ctxBase.httpClient);
  // completed 路径回收扫描上下文（TTL 到期清 scans + eventBus + 限速桶）
  sm._retire(scanId);
}

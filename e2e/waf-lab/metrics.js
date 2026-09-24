// e2e/waf-lab/metrics.js
// 纯函数：计算检出率 / 拦截率（百分比，保留 1 位小数），便于单测与 e2e 复用。
//
// 口径（对齐 PRD §6.2）：
//   检出率   = 被确认 vulnerable 的注入点数 / 总注入点数 * 100
//   拦截率   = 被 WAF 拦截(403)的请求数 / 总请求数 * 100
export function computeMetrics({
  totalPoints,
  detectedA,
  detectedB,
  blockedReqA,
  blockedReqB,
  totalReqA,
  totalReqB,
}) {
  const rate = (n, d) => (d ? +((n / d) * 100).toFixed(1) : 0);
  return {
    totalPoints,
    detectedA,
    detectedB,
    detectRateA: rate(detectedA, totalPoints),
    detectRateB: rate(detectedB, totalPoints),
    blockedReqA,
    blockedReqB,
    blockRateA: rate(blockedReqA, totalReqA),
    blockRateB: rate(blockedReqB, totalReqB),
  };
}

/**
 * A/B 实验判据。**必须先过有效性前置，再看两条 WAF 侧判据。**
 *
 * 有效性前置（detectedA/detectedB 均须 ≥1）不是装饰：本实验要证明的是
 * 「tamper 让请求**穿透**了 WAF」，而穿透的前提是 payload 真的被执行了。
 * 两侧零检出时，「拦截率下降」完全可能只是因为扫描器不再发可执行的东西 ——
 * 结论方向反了也不会红。
 *
 * 实测代价（2026-09-25）：A3 通道降级初版把 CRS 画像下的 error 通道判死，
 * 本装置 configA 从 1/1 检出掉到 **0/1**、请求数 175→246，而 `passed` 仍为
 * true、退出码 0、报告照印「tamper 确已绕过 WAF ✅」。缺陷由另一笔提交收窄
 * 判据修掉，门禁全程没红过一次。
 *
 * @returns {{valid:boolean, validityReasons:string[], blockRateDrop:boolean,
 *            highRiskDrop:boolean, passed:boolean}}
 */
export function evaluateAbExperiment({
  totalPoints,
  detectedA,
  detectedB,
  blockRateA,
  blockRateB,
  highRiskA,
  highRiskB,
}) {
  const reasons = [];
  if (!(totalPoints >= 1)) {
    reasons.push(`靶场未识别到任何注入点（totalPoints=${totalPoints}）—— 扫描未跑完或靶子坏了`);
  }
  if (!(detectedA >= 1)) reasons.push(`configA（tamper 关）零检出（${detectedA}/${totalPoints}）`);
  if (!(detectedB >= 1)) reasons.push(`configB（tamper 开）零检出（${detectedB}/${totalPoints}）`);
  const valid = reasons.length === 0;

  const blockRateDrop = blockRateB < blockRateA;
  const highRiskDrop = highRiskB < highRiskA;
  return {
    valid,
    validityReasons: reasons,
    blockRateDrop,
    highRiskDrop,
    passed: valid && blockRateDrop && highRiskDrop,
  };
}

export default computeMetrics;

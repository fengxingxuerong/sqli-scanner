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

export default computeMetrics;

// ============================================================================
// responseTiming.js —— 整条传输耗时的非枚举元数据（抽自 HttpClient.request）
//
// [D199] 抽取原因：HttpClient.request 的函数体与圈复杂度都贴着「只许持平或变浅」的基线，
// --retry-on 新增一个重试分支后必须把等量职责移出；本块是内聚度最高的纯写入动作。
// 非枚举属性是硬约束：污染 JSON 序列化会把计时字段写进报告/日志/请求头透传路径。
// ============================================================================

/**
 * @param {object} res 响应对象（原地挂属性）
 * @param {number|null} t0Net 令牌获取完成后的计时起点；null = 未开启 networkTiming
 * @returns {void}
 */
export function attachNetworkTiming(res, t0Net) {
  if (t0Net === null || !res || typeof res !== 'object') return;
  Object.defineProperty(res, '__networkMs', {
    value: performance.now() - t0Net,
    enumerable: false,
    configurable: true,
    writable: true,
  });
}

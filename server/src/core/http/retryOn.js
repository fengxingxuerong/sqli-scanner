// ============================================================================
// retryOn.js —— [D199 对标 sqlmap --retry-on] 状态码命中即重试的纯判据
//
// 抽成纯函数的理由：HttpClient.request 的重试循环夹着 SSRF/限速/认证重放，
// 用 mock 全链路自证「重试了几次」容易把环境噪声读成判据；判据本身应可零网络验证。
// 接线由 server/tests/d199WireToggles.test.js 的源码守卫钉住（剔注释后结构性紧邻）。
// ============================================================================

/**
 * 编译状态码正则。非法表达式退化为 null（= 不启用），正常路径已在 CLI/REST 入口预编译校验。
 * @param {unknown} raw 正则串
 * @returns {RegExp|null}
 */
export function compileRetryOn(raw) {
  if (!raw) return null;
  try {
    return new RegExp(String(raw));
  } catch {
    return null;
  }
}

/**
 * 本次响应是否需要按 --retry-on 再试一轮。
 * 余量用尽（attempt >= retry）时**不重试**，把最后一次响应原样交回上层判定 ——
 * 不能因为状态码抖动就吞掉响应或改变退出语义。
 * @param {RegExp|null} re 已编译正则
 * @param {{status?: number|string}|null} res 响应
 * @param {number} attempt 当前轮次（0 起）
 * @param {number} retry 最大重试次数
 * @returns {boolean}
 */
export function shouldRetryOnStatus(re, res, attempt, retry) {
  if (!re || attempt >= retry) return false;
  re.lastIndex = 0; // 防用户正则带 g/y 时跨轮次 lastIndex 漂移
  return re.test(String(res?.status ?? ''));
}

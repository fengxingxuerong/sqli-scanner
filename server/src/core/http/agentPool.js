// ============================================================================
// agentPool.js —— Agent 连接池上限推导 + TLS 证书错误码 + 响应超限判定
//
// 从 httpClient.js 抽离，[阶段② 拆上帝对象 2026-09-13]。
// 职责边界：只负责「连接资源预算」与两类错误判定，不持有连接实例本身。
// ============================================================================
import defaults from '../../config/defaults.js';

// 证书类错误（默认严格校验下自签/内网 CA 目标必然命中）：给出可操作提示，避免「扫不出」无痕
export const TLS_CERT_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
  'CERT_UNTRUSTED',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
]);

// axios 通道超限的判定（message 由 axios http adapter 给出，无独立错误码）
export function isMaxContentLengthError(err) {
  if (!err) return false;
  return /maxContentLength|maximum response length/i.test(String(err.message || ''));
}

// 显式 HTTP/HTTPS Agent（keep-alive + 连接复用），与 Node 版本解耦（原逻辑不变）
// ── 连接池上限与配置并发对齐（B-perf）──
// 旧值固定 maxSockets:50，与配置并发脱钩（无限收敛的本意是防 Agent 无上限放大）。
// 现按部署的理论在途峰值推导：并发扫描上限（MAX_SCAN_API_CONCURRENT，默认 8）× 单扫描并发
// （defaults.concurrency，默认 4）= 32，且不低于 max(concurrency*2, 16)；既不无限放大，
// 也不低于实际并发需求造成跨扫描排队。可用 HTTP_AGENT_MAX_SOCKETS 显式覆盖（≥1）。
// 注意：Agent 为模块级共享（服务所有扫描），用户按扫描覆盖 concurrency 不影响本上限——
// 超出上限的并发请求会在 Agent 排队（不报错、不丢请求），极端部署请用环境变量调高。
/**
 * 按部署的理论在途峰值推导 Agent maxSockets：
 * 并发扫描上限 × 单扫描并发，且不低于 concurrency*2 和 16。
 * @param {number} concurrency 单扫描并发数
 * @param {number} maxConcurrentScans 最大同时扫描数
 * @returns {number} Agent maxSockets 值
 */
export function computeAgentMaxSockets(concurrency, maxConcurrentScans) {
  const c = Number.isFinite(concurrency) && concurrency > 0 ? concurrency : defaults.concurrency || 4;
  const m =
    Number.isFinite(maxConcurrentScans) && maxConcurrentScans > 0
      ? maxConcurrentScans
      : Number(process.env.MAX_SCAN_API_CONCURRENT) || 8;
  return Math.max(c * m, c * 2, 16);
}
export const AGENT_MAX_SOCKETS = (() => {
  const env = Number(process.env.HTTP_AGENT_MAX_SOCKETS);
  if (Number.isFinite(env) && env >= 1) return Math.round(env);
  return computeAgentMaxSockets(defaults.concurrency, Number(process.env.MAX_SCAN_API_CONCURRENT) || 8);
})();

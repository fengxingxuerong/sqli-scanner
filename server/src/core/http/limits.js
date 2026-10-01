// =====================================================================
// limits.js — httpClient 模块级常量与小工具：体积上限 / 重试码 / 退避基值 /
// WAF jitter / 扫描停止取消错误。
// 自 httpClient.js 拆出（纯搬移），由 core/http 各模块与 httpClient.js 共用。
// =====================================================================
// 不可重试的错误码（原逻辑不变）
export const NON_RETRYABLE_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'CERT_HAS_EXPIRED',
  'ERR_SSL_SSLV3_ALERT',
]);

// 响应/请求体积上限（P1-3）：SSRF_MAX_BODY_MB 可覆盖。
// [P1-FIX 2026-09-08 ④] 默认 5MB→10MB：真实站点「首页 + 静态资源」常 1-3MB，带大表格的列表页
// 直接超限 —— 超限在 undici 通道是静默截断（检测器只看 data/status → 漏检），提高默认值比
// 「让用户去查环境变量名」更能止血；仍可用 SSRF_MAX_BODY_MB 下调（低内存部署）。
// 提取路径（dumpData）可传 opts.maxContentLength 请求更大的上限（如 50MB），避免大表拖库被截断。
export const MAX_BODY_BYTES = (() => {
  const mb = Number(process.env.SSRF_MAX_BODY_MB) || 10;
  return Math.max(1, mb) * 1024 * 1024;
})();
export const EXTRACT_MAX_BODY_BYTES = (() => {
  const mb = Number(process.env.EXTRACT_MAX_BODY_MB) || 50;
  return Math.max(1, mb) * 1024 * 1024;
})();
// --delay 单次延时上限（秒）：防止把毫秒值当秒传入导致请求长时间挂起
export const MAX_DELAY_SEC = 60;
// --max-requests 计数表最大条目数：超出后清理最早写入的条目，防异常退出残留累积
export const MAX_TRACKED_SCANS = 512;

export const BACKOFF_BASE_MS = 100;
export const BACKOFF_MAX_MS = 1000;

export async function applyJitter(wafEvasion) {
  if (wafEvasion && wafEvasion.jitterMs > 0) {
    const ms = Math.floor(Math.random() * wafEvasion.jitterMs);
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// [⑮] 扫描停止触发的请求取消错误（原 request() 内三处内联构造统一到此）
export function newAbortError() {
  const abortErr = /** @type {NodeJS.ErrnoException} */ (new Error('请求已取消（扫描停止）'));
  abortErr.name = 'AbortError';
  abortErr.code = 'ERR_CANCELED';
  return abortErr;
}

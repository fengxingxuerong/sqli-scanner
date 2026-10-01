// =====================================================================
// scanScope.js — 逐跳授权范围（scope）校验 + 出口 SSRF/scope 阶段方法。
// 自 httpClient.js 拆出（纯搬移）：_assertEgressAllowed 由 HttpClient.prototype 挂载。
// =====================================================================
import { getScopeForScan, assertInScope } from '../scopeGuard.js';
import { assertSafeTargetForEgress } from './egressGuard.js';
import { ErrorCode, AppError } from '../errors.js';

// ── [P0-SEC 2026-09-08] 逐跳授权范围（scope）校验 ────────────────────────────────
// 为什么必须在这里而不是只在 API 入口：目标 302 到未授权主机很常见（统一登录跳转、CDN 回源、
// 灰度切流），而扫描器会跟着跳并把后续全部注入请求（含 Cookie/Authorization）打到新主机上。
// 只在 /scan/start 校一次 = 圈外主机被当成圈内目标打完且无人知情，属事故级缺口。
// scope 按 scanId 登记在 scopeGuard（见 registerScanScope），未登记时恒为放行（零行为变化）。
/**
 * @param {string|undefined} scanId 扫描级上下文带 scanId（forScan 注入）；无则不校验
 * @param {string} urlString 本次即将出站的 URL（含重定向后的每一跳）
 */
export async function assertScanScope(scanId, urlString) {
  if (!scanId || !urlString) return;
  const scope = getScopeForScan(scanId);
  if (!scope) return;
  assertInScope(String(urlString), scope);
}

  /**
   * [P0-1] 出口统一 SSRF 校验 + [P0-SEC] 授权范围（scope）逐请求校验。
   * 直连模式（req.sql）无 URL，跳过。
   * [P1-FIX ②] 已走代理且 ssrfViaProxy!=='off' → 解析/严格层判定下放至代理（硬底线段仍无条件拒）。
   */
export async function _assertEgressAllowed(opts, egress) {
    if (!opts.url) return;
    await assertSafeTargetForEgress(opts.url, egress).catch((e) => {
      if (e instanceof AppError) throw e;
      throw new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
    });
    // [P0-SEC] 授权范围（scope）逐请求校验：目标 URL 在 start 时校过，但爬虫/二阶/safeUrl/
    // 手工构造的注入请求都可能指向另一个主机，统一在出口拦一次。
    await assertScanScope(opts.scanId, opts.url);
  }

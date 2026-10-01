// =====================================================================
// redirects.js — 手动重定向跟随（HTTP/1.1 与 HTTP/2 双路径）：每跳 SSRF + scope
// 重校验、跨域剥离凭据头、DNS 钉死、每跳 Set-Cookie 捕获。
// 自 httpClient.js 拆出（纯搬移）：由 HttpClient.prototype 挂载（this 语义不变）。
// =====================================================================
import { URL } from 'url';
import { assertSafeTargetForEgress, buildPinnedLookup } from './egressGuard.js';
import { assertScanScope } from './scanScope.js';
import {
  isCrossOriginRedirect, resolveRedirectMethod, applyRedirectHeaders,
} from './redirectPolicy.js';

  // 手动重定向跟随（P0-1）：最多 5 跳，每跳校验 Location 的 SSRF 策略
  // [P2-5] --ignore-redirects：redirects 传 0 时完全忽略 3xx（直接返回首跳跳转响应），
  // 对标 sqlmap --ignore-redirects（“不跟随重定向，直接返回 3xx”）。
  /**
   * 手动逐跳跟随重定向（最多 5 跳）：每跳 SSRF 校验 + 跨域剥离凭据头 + DNS 钉死。
   * egress 标注 any：它是出口语义透传对象（viaProxy/proxySource/insecureTls/ssrfViaProxy
   * 等字段随调用链演进），逐字段声明只会不断失配。
   * @param {any} initial
@param {any} opts
@param {any} headers
@param {any} proxyConf
   * @param {number} timeoutMs
@param {boolean} disableKA
@param {any} redirects
   * @param {any} egress
@returns {Promise<any>}
   */
export async function _followRedirects(initial, opts, headers, proxyConf, timeoutMs, disableKA, redirects, egress = null) {
    let current = initial;
    let currentUrl = opts.url;
    let redirectsLeft = redirects ?? 5;
    // [P0-FIX] 跨域跳转剥离敏感头：axios 每跳复用同一 headers 对象，
    // 目标站 302 到第三方域时原始 Host 的 Cookie/Basic Auth/Bearer 会被原样转发 → 凭据泄露。
    // 克隆一层：跨域跳转时从副本剥离凭据头（不污染原对象，后续同域跳转仍带凭据）。
    let activeHeaders = headers;
    while (redirectsLeft-- > 0) {
      this._captureCookies(currentUrl, current, opts); // 每跳捕获 Set-Cookie（幂等）
      const status = current.status;
      if (status >= 300 && status < 400 && current.headers && current.headers.location) {
        // 每跳基于「当前请求 URL」解析相对 Location（多跳链正确性）
        const nextUrl = new URL(String(current.headers.location), currentUrl).toString();
        await assertSafeTargetForEgress(nextUrl, egress); // 每跳重新校验（P0-1；[P1-FIX ②] 代理模式按同一 egress 下放）
        await assertScanScope(opts?.scanId, nextUrl); // [P0-SEC] 跳转目标同样受授权范围约束
        // [大文件二期拆分 2026-09-20] 跨域判定 / 方法降级 / 凭据头剥离三条安全判定
        // 已抽为 http/redirectPolicy.js 的纯函数（与 H2 路径共用同一份语义）。
        const crossOrigin = isCrossOriginRedirect(currentUrl, nextUrl);
        activeHeaders = applyRedirectHeaders(activeHeaders, headers, crossOrigin);
        const method = resolveRedirectMethod(status, opts.method || 'GET');
        current = await this._rawRequest(
          // [P0-3] 重定向每跳也传 pinnedLookup（对重定向 URL 重新解析 DNS 钉死）
          { method, lookup: buildPinnedLookup(nextUrl) },
          // [P0-4] 重定向到 GET 时清空 body（防 POST body 透传到 GET 请求，避免请求体异常或意外数据泄露）
          { ...opts, url: nextUrl, method, data: method === 'GET' ? undefined : opts.data },
          activeHeaders,
          proxyConf,
          timeoutMs,
          disableKA
        );
        currentUrl = nextUrl;
        continue;
      }
      return current;
    }
    return current; // 超过 5 跳：返回最后一个响应（不再跟随）
  }

  // [P0-FIX] HTTP/2 手动重定向跟随：undici 内置跟随已关闭（maxRedirections: 0），

  // 本方法逐跳跟随（最多 5 跳），每跳与 HTTP/1.1 路径一致地：
  //   ① assertSafeHttpTarget 校验跳转目标（防 302 跳内网/云元数据绕过出口 SSRF 防护）；
  //   ② 跨域（hostname/protocol 变化）时剥离 Authorization/Cookie 等凭据头（防凭据泄露到第三方域）；
  //   ③ 对跳转 URL 重新 DNS 钉死（防 rebinding）。
  // [P2-5] --ignore-redirects：redirects 传 0 时忽略 3xx（HTTP/2 路径与 HTTP/1.1 一致）
  /**
   * 手动逐跳跟随重定向（内置跟随已关闭，见 maxRedirections: 0）。
   * egress 标注为 any：它是出口语义透传对象（含 viaProxy/proxySource/insecureTls/ssrfViaProxy
   * 等字段，随调用链演进），在此逐字段声明只会不断失配。
   * @param {any} opts
@param {any} headers
@param {number} timeoutMs
   * @param {any} redirects
@param {any} egress
@returns {Promise<any>}
   */
export async function _followRedirectsH2(opts, headers, timeoutMs, redirects, egress = null) {
    let currentUrl = opts.url;
    let activeHeaders = headers;
    let redirectsLeft = redirects ?? 5;
    let current = await this._rawUndici(
      { ...opts, url: currentUrl },
      activeHeaders,
      timeoutMs,
      buildPinnedLookup(currentUrl)
    );
    while (redirectsLeft-- > 0) {
      this._captureCookies(currentUrl, current, opts); // 每跳捕获 Set-Cookie（幂等）
      const status = current.status;
      if (status >= 300 && status < 400 && current.headers && current.headers.location) {
        // 多值头下 location 可能是 string[] → 显式收窄为 string
        const nextUrl = new URL(String(current.headers.location), currentUrl).toString();
        await assertSafeTargetForEgress(nextUrl, egress); // 每跳重新校验（P0-1；[P1-FIX ②] 代理模式按同一 egress 下放）
        await assertScanScope(opts?.scanId, nextUrl); // [P0-SEC] 跳转目标同样受授权范围约束
        // [大文件二期拆分 2026-09-20] 三条安全判定改用 http/redirectPolicy.js 纯函数，
        // 与 H1 路径共用同一份语义（此前两处各自实现，凭据头删除的大小写处理不一致）。
        const crossOrigin = isCrossOriginRedirect(currentUrl, nextUrl);
        activeHeaders = applyRedirectHeaders(activeHeaders, headers, crossOrigin);
        const method = resolveRedirectMethod(status, opts.method || 'GET');
        current = await this._rawUndici(
          { ...opts, url: nextUrl, method, data: method === 'GET' ? undefined : opts.data },
          activeHeaders,
          timeoutMs,
          buildPinnedLookup(nextUrl)
        );
        currentUrl = nextUrl;
        continue;
      }
      return current;
    }
    return current; // 超过 5 跳：返回最后一个响应（不再跟随）
  }

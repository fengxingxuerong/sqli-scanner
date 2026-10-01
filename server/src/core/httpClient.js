// ============================================================================
// httpClient.js —— HTTP 客户端（SSRF 防护 + 体积上限 + 日志打码 + 限速 + DNS 钉死）
// 功能：
//   SSRF：出口请求统一校验目标 IP（分层策略：元数据/链路本地默认永远拒绝；
//          SSRF_STRICT=1 时连回环/私网也拒绝；SSRF_ALLOW_PRIVATE=1 或 SSRF_ALLOW_CIDRS 显式放行）
//   重定向：手动逐跳跟随 + 每跳重新校验 + DNS 钉死（防 302 跳内网 + DNS rebinding）
//   体积上限（maxContentLength/maxBodyLength，默认 5MB，可 SSRF_MAX_BODY_MB 覆盖）
//   日志打码：URL query 值剥离（防注入 payload 与敏感参数进日志）
//   头名黑名单（host/transfer-encoding/content-length/connection/upgrade 等禁止覆写）
//   限速：TokenBucket 串行化（任意并发下平均速率 ≤ ratePerSec）
//   DNS 钉死：buildPinnedLookup 将校验 IP 固定给请求层（防 DNS rebinding TOCTOU）
//   HTTP/2（对标 sqlmap --http2）：config.http2 === true 时，对目标首选 HTTP/2（undici ALPN 协商；
//   目标不支持 H2 自动降级 HTTP/1.1）。默认关闭（axios HTTP/1.1，零行为变化）。
// [P1-FIX 2026-09-08] 实战发包层四项修复（配置键见 defaults.js 同名注释）：
//   ① insecureTls：自签/内网 CA 目标可扫（axios 侧专用 httpsAgent、undici 侧 connect.rejectUnauthorized，
//      按 {insecure,keepAlive} 组合缓存 Agent，不污染模块级共享 Agent 池）。
//   ② 代理：scheme 白名单（socks4/socks4a 不再被当成 http 明文代理）+ *PROXY/NO_PROXY 环境变量
//      （trustProxyEnv）+ ssrfViaProxy（已走代理时把「解析 + 私网判定」下放给代理，硬底线段仍拒）。
//   ③ 响应体按 Content-Type/HTML <meta> 声明的字符集解码（GBK/Big5/Shift-JIS/EUC-KR/… 不再不可逆
//      变 U+FFFD），对外契约仍是 string —— 检测器零改动。
//   ④ 响应体超限不再「静默」：两条通道统一挂 res.__meta = { bodyBytes, truncated, charset,
//      insecureTls, viaProxy }（非枚举属性），超限同时 warn 一次。
//   ⑤ [P0-SEC] 每一跳（含重定向）额外过一遍授权范围（scopeGuard），越界直接拒发。
// 测试套件本地起 mock 目标（127.0.0.1）时请设置环境变量 SSRF_ALLOW_PRIVATE=1。
// ============================================================================
// [五期拆分 2026-10-01] 编排主干留守本文件（constructor/request/_prepareHeaders/
// _sendFollowRedirects/forScan/headRequest/close），其余按职责搬至 core/http/ 同级模块
// （limits/scanScope/sessionState/transport/redirects/auth/retry），方法体逐行原样、
// 由 HttpClient.prototype 挂载（this 语义不变）——调用方与测试的 import 路径全部不变。

import axios from 'axios';
// [P0-SEC 2026-09-08] 逐跳授权范围校验（scope）：目标 302 到圈外主机时，后续全部注入请求
// （含 Cookie/Authorization）会跟着跑出去，只在 API 入口校一次拦不住。scope 按 scanId 登记。
import { Agent as UndiciAgent } from 'undici';
import { defaults } from '../config/defaults.js';
import { ErrorCode, AppError } from './errors.js';
// [P1-2026-09-14] NTLM 三步握手（对标 sqlmap --auth-type=NTLM）：Type1 → Type2(challenge) → Type3
import { NtlmHandshake } from './ntlmHandshake.js';
// [大文件二期拆分 2026-09-14] SSRF/代理/一次性日志已抽至 core/http/ 下独立模块；
// 下方 re-export 保证既有 import 路径不变（外部模块与测试仍可从 httpClient.js 取到这些符号）。
import {
  isBlockedIp, resolveHost, buildPinnedLookup,
  assertSafeHttpTarget, assertSafeTargetForEgress, dnsCache,
  noteEgressIpFailure,
} from './http/egressGuard.js';
import {
  assertProxyUsable, isLocalOrPrivateHost, isNoProxyHost, resolveProxy,
} from './http/proxy.js';
import { warnInsecureTls } from './http/logOnce.js';
// [大文件二期拆分 2026-09-20] 重定向的纯决策逻辑（跨域判定 / 方法降级 / 凭据头剥离）：
// H1 与 H2 两条跟随路径共用同一份安全语义，且可脱离 I/O 直接单测。
// 注：dnsCache / EXTRACT_MAX_BODY_BYTES 等由文件尾部原有 export 语句导出，此处不重复导出。
// 下面这行是**兼容再导出**：这些符号虽已搬走，但既有调用方（含测试）仍从 httpClient.js 取，
// 保持路径不变 = 拆分对调用方零影响（netErrGuard.test.js 就依赖 resolveProxy/isLocalOrPrivateHost）。
export {
  assertSafeHttpTarget, assertSafeTargetForEgress, isBlockedIp, resolveHost,
  assertProxyUsable, isLocalOrPrivateHost, isNoProxyHost, resolveProxy,
  noteEgressIpFailure,
};

// ── [P1-FIX 2026-09-08 ①] TLS/代理 Agent 组装已抽至 core/http/agentFactory.js（四期拆分 2026-09-30）
// 下方 import + re-export 保证既有 import 路径不变（httpClient.p2.test.js 等仍从本文件取 buildProxyAgent）。
import { agentsForTls, buildProxyAgent, httpAgent, httpsAgent } from './http/agentFactory.js';
export { agentsForTls, buildProxyAgent };

/**
 * [P1-FIX 2026-09-08 ③] 响应体字符集解码
 * 旧实现 responseType:'text' → axios 无条件按 utf8 解码：GBK/Big5/Shift-JIS/EUC-KR/Windows-1252
 * 目标（老 Java/ASP/JSP 站极常见）被解成 U+FFFD 且不可逆 —— 中文报错文案丢失、布尔比对出现字节
 * 碰撞（不同字节序列映射成同一替换符 → 差异消失 → 漏检）、拖库出的中文数据是乱码。
 * 现在两条通道统一先取原始字节、再按声明字符集解码，对外仍是 string。
 */
// 再导出：既有 import 路径保持不变（外部模块与测试仍可从 httpClient.js 取到这些符号）
// [五期拆分] attachResMeta 在 request() 内仍在用，需同时 import（re-export 不绑定本模块作用域）。
import { attachResMeta } from './http/responseCodec.js';
import { AGENT_MAX_SOCKETS } from './http/agentPool.js';
export {
  decompressResponseBody,
  detectResponseCharset,
  decodeResponseBody,
  getResMeta,
  attachResMeta,
} from './http/responseCodec.js';
// 再导出：既有 import 路径保持不变（外部模块与测试仍可从 httpClient.js 取到这些符号）
export {
  computeAgentMaxSockets,
  AGENT_MAX_SOCKETS,
} from './http/agentPool.js';

import { TokenBucket } from './http/tokenBucket.js';
// 再导出：保持既有 import 路径不变（defaults.js / ScanManager.js / 测试仍从 httpClient.js 取）
export { TokenBucket } from './http/tokenBucket.js';

import { pickRandomUA } from './http/userAgents.js';
// 再导出：保持既有 import 路径不变
export { pickRandomUA } from './http/userAgents.js';

// ── 认证头合并 / 日志脱敏 / 出口语义：已抽至 core/http/requestContext.js（三期拆分 2026-09-22）
// 下方 import + re-export 保证既有 import 路径不变（外部模块与测试仍从 httpClient.js 取）。
import {
  mergeAuthHeaders,
  logSafeUrl,
  effectiveInsecureTls,
  resolveEgressPolicy,
} from './http/requestContext.js';
export { mergeAuthHeaders, logSafeUrl, effectiveInsecureTls, resolveEgressPolicy };

// [五期拆分 2026-10-01] 常量与阶段方法已搬至 core/http/*（limits/scanScope/sessionState/
// transport/redirects/auth/retry），此处只 import facade 用到的符号 + 原型挂载所需的方法体。
import { MAX_BODY_BYTES, EXTRACT_MAX_BODY_BYTES, applyJitter } from './http/limits.js';
import { _assertEgressAllowed } from './http/scanScope.js';
import {
  createBucket, removeBucket, removeRequestCount,
  jarFor, clearJar, _captureCookies, _evictRequestCounts, bucketForRate, _resolveRateBucket,
} from './http/sessionState.js';
import { undiciAgentInsecure, _rawRequest, _finishResponse, _rawUndici } from './http/transport.js';
import { _followRedirects, _followRedirectsH2 } from './http/redirects.js';
import { _digestAuthHeader, _digestReplay, _setDigestChallenge, _after401 } from './http/auth.js';
import { _beforeAttempt, _onRequestError, _sleep } from './http/retry.js';
export { dnsCache, EXTRACT_MAX_BODY_BYTES, MAX_BODY_BYTES };

export class HttpClient {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.disableKeepAlive] 关闭长连接（对标 sqlmap --keep-alive 关闭）
   */
  constructor({ disableKeepAlive } = {}) {
    this.bucket = new TokenBucket(defaults.ratePerSec);
    this.buckets = new Map();
    this.rateBuckets = new Map();
    // [sqlmap 对标] --max-requests：按 scanId 跟踪请求计数，达上限后拒绝新请求
    this._requestCounts = new Map();
    // [P2-4 --auth-type=Digest] 每主机 Digest 挑战状态缓存：{ challenge, nc, username, password }
    // 对标 curl --digest：challenge 一旦取得即缓存复用，nc 每次请求单调递增防重放；
    // 服务端 401 刷新（nonce 过期）时更新 challenge 并重算，避免死循环。
    this._digestStates = new Map();
    // [P1-2026-09-14] NTLM 三步握手状态机（独立模块，避免 httpClient 继续膨胀）
    this._ntlm = new NtlmHandshake();
    // [P1-FIX 2026-09-05] Cookie Jar（对标 sqlmap 自动会话保持）：scanId -> CookieJar，
    // 请求自动携带服务端 Set-Cookie 回发的会话，扫描退役时 clearJar 一并清理
    this._jars = new Map();
    this.disableKeepAlive = disableKeepAlive === true || defaults.disableKeepAlive === true;
    // [P1-FIX ①] insecureTls 专用 undici Agent 槽位（惰性创建：默认路径零开销、零行为变化）
    this._undiciAgentInsecure = null;
    this.instance = axios.create({
      timeout: defaults.timeoutMs,
      // 重定向改为手动跟随（P0-1）：每跳重新做 SSRF 校验
      maxRedirects: 0,
      maxContentLength: MAX_BODY_BYTES, // P1-3 响应体积上限
      maxBodyLength: MAX_BODY_BYTES, // P1-3 请求体积上限
      ...(this.disableKeepAlive ? {} : { httpAgent, httpsAgent }),
      validateStatus: () => true,
    });
    // [HTTP/2] undici Agent：config.http2 开启时用于发起 HTTP/2 请求（ALPN 协商，
    // 目标不支持 H2 自动降级 HTTP/1.1）。connect 关闭 TLS 会话缓存依赖 keep-alive 复用来提速。
    this.undiciAgent = new UndiciAgent({
      connect: { timeout: defaults.timeoutMs },
      connections: AGENT_MAX_SOCKETS,
      pipelining: 1,
    });
  }

  /**
   * 销毁底层 HTTP Agent（undici / http / https），释放连接池。
   * 在引擎优雅关闭时调用，防 keep-alive 连接泄漏。
   */
  close() {
    try { this.undiciAgent?.close?.(); } catch { /* ignore */ }
    try { this.undiciAgent?.destroy?.(); } catch { /* ignore */ }
    try { this._undiciAgentInsecure?.close?.(); } catch { /* ignore */ }
    try { this._undiciAgentInsecure?.destroy?.(); } catch { /* ignore */ }
    try { httpAgent.destroy?.(); } catch { /* ignore */ }
    try { httpsAgent.destroy?.(); } catch { /* ignore */ }
  }

  forScan(scanId, ratePerSec) {
    this.createBucket(scanId, ratePerSec);
    const self = this;
    return {
      request: (opts) => self.request({ ...opts, scanId }),
      // [sqlmap 对标] --null-connection：per-scan 客户端也暴露 headRequest，自动注入 scanId
      headRequest: (url, opts) => self.headRequest(url, { ...opts, scanId }),
    };
  }

  async request(opts) {
    const retry = opts.retry ?? defaults.retry;
    const timeoutMs = opts.timeoutMs ?? defaults.timeoutMs;
    // [P2-5] --force-ssl：http:// 目标强制升级 https（对标 sqlmap --force-ssl：
    // 强制使用 SSL 连接。适用于目标实际监听 443 但 URL 写成 http 的场景；
    // 在 SSRF 校验前改写，后续所有安全机制（校验/DNS 钉死/代理）作用于改写后的 URL）。
    // 注意：仅改写协议，host/port/path 原样；非 http 协议（direct/sql）无 URL 不受影响。
    if (opts.forceSsl && typeof opts.url === 'string' && /^http:\/\//i.test(opts.url)) {
      opts.url = opts.url.replace(/^http:\/\//i, 'https://');
    }
    // [P1-FIX 2026-09-08 ①②] 先确定本次请求的「出口语义」（代理 / 证书校验 / 目标校验下放），
    // 再据此做 SSRF 校验 —— 顺序很关键：是否走代理决定本地能否解析目标，insecureTls 决定挂哪套 Agent。
    // [三期拆分 2026-09-22] 该决策整体抽为纯函数 resolveEgressPolicy（含 socks5 本地解析提示）。
    const { insecureTls, proxyUrl, egress } = resolveEgressPolicy(opts);
    if (insecureTls) warnInsecureTls();
    // P0-1：出口统一 SSRF 校验 + [P0-SEC] scope 逐请求校验（阶段方法 _assertEgressAllowed）
    await this._assertEgressAllowed(opts, egress);

    // [P2-5] --ignore-redirects：跟随上限置 0 → 3xx 直接返回不跳转
    const redirectsLeft = opts.ignoreRedirects === true ? 0 : 5;
    // [sqlmap 对标] --reqrate：reqRate > 0 时覆盖 ratePerSec 作为 TokenBucket 速率
    const effectiveRate = (opts.reqRate && opts.reqRate > 0) ? opts.reqRate : opts.ratePerSec;
    const bucket = this._resolveRateBucket(opts, effectiveRate);
    // [P1-FIX ①②] 代理来源已在入口统一解析（含环境变量），insecureTls 一并决定 Agent 组合
    const proxyConf = buildProxyAgent(/** @type {string} */ (proxyUrl), { insecureTls });
    const disableKA = opts.disableKeepAlive === true || this.disableKeepAlive === true;
    // 头合并（含 P2-8 头名黑名单过滤 / randomUA / Cookie Jar / Digest·NTLM 预附加）
    const { headers, digestPreAttached } = this._prepareHeaders(opts);
    // 单次发送（HTTP/2 与 axios 两条通道 + 手动重定向跟随），重试与认证重放共用本闭包。
    // [P0-3] DNS 钉死：从缓存取已校验 IP，传给请求层避免二次解析（防 DNS rebinding），
    // 仅在 assertSafeHttpTarget 已成功校验过该 URL 时生效。
    // [P0-FIX 2026-09-09] 钉死 IP 在每次派发瞬间重新获取（原实现整条请求只算一次，
    // 重试必然又打同一个死 IP）——取 IP 的时机与原实现逐点一致。
    const send = () =>
      this._sendFollowRedirects(opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
    let lastErr;
    for (let attempt = 0; attempt <= retry; attempt++) {
      // 每次尝试前的闸门：abort 检查 / --max-requests 计数 / --delay 延时（见 _beforeAttempt）
      await this._beforeAttempt(opts);
      try {
        await bucket?.acquire(); // [P0-FIX 2026-09-14] bucket 可为 null（不限速直通）
        await applyJitter(opts.wafEvasion);
        // networkTiming（MERGED: perf 版）：从「令牌获取完成之后」计网络耗时，供时间盲注判定
        // 剔除限速排队等待（限速低时并发采样的排队时间会被旧 __elapsed 计入，导致基线虚高）。
        const t0Net = opts.networkTiming === true ? performance.now() : null;
        let res = await send();
        // 401 → Digest 挑战-重放 / NTLM 三步握手（可能内部经 send() 重发并返回最终响应）
        res = await this._after401(res, opts, headers, send, digestPreAttached);
        if (t0Net !== null && res && typeof res === 'object') {
          // 非枚举属性：不污染任何 JSON 序列化/请求头透传路径
          // [P1-FIX ②] 计时点覆盖整条传输（含代理往返）：走 Burp/socks 时 __networkMs =
          // 「本地↔代理目标」全往返，故 jitterMs 与时间盲注阈值不得按本地 RTT 标定；
          // 此处只加 __meta.viaProxy 标注（不改判定公式，避免回归）。
          Object.defineProperty(res, '__networkMs', {
            value: performance.now() - t0Net,
            enumerable: false,
            configurable: true,
            writable: true,
          });
        }
        // [P1-FIX ④] 出口语义写进响应元数据（与 __networkMs 同样非枚举）：
        // 上层/报告据此标注「本次扫描未校验证书」「响应被截断」「流量经代理」，检测判定不变。
        if (res && typeof res === 'object') {
          attachResMeta(res, {
            insecureTls: egress.insecureTls,
            viaProxy: egress.viaProxy,
            ...(egress.viaProxy ? { proxySource: egress.proxySource } : {}),
          });
        }
        return res;
      } catch (err) {
        lastErr = err;
        // [P0-FIX] 终态错误（SSRF 拒绝 / 取消 / 超限 / 不可重试码 / 最终超时）在
        // _onRequestError 内直接抛出；可重试错误在此完成退避等待并正常返回
        // → 进入下一轮 attempt（与原 catch 内 continue 语义一致）。
        await this._onRequestError(err, opts, attempt, retry);
      }
    }
    throw new AppError(ErrorCode.HTTP_ERROR, lastErr?.message || 'HTTP 请求失败');
  }

  /**
   * 请求头准备：合并认证头（含 P2-8 头名黑名单过滤）→ randomUA → Cookie Jar 会话合并 →
   * Digest/NTLM 预附加（已持有 state 时发送前即带 Authorization，省一次 401 往返；
   * 用户显式 Authorization 优先，不干预）。
   * @returns {{headers: object, digestPreAttached: boolean}}
   */
  _prepareHeaders(opts) {
    let headers = mergeAuthHeaders(opts.headers || {}, opts.auth ?? defaults.auth ?? null);
    if (opts.wafEvasion && opts.wafEvasion.randomUA) {
      // randomUA==='mobile'（CLI --mobile）→ 仅从移动端池取；其余真值 → 全池
      headers['User-Agent'] = pickRandomUA(opts.wafEvasion.randomUA);
    }
    // [P1-FIX 2026-09-05] Cookie Jar：请求前合并扫描会话 cookie（用户显式 Cookie 优先，同名不覆盖；
    // opts.cookieJar===false 关闭，对标无 jar 行为零回归）
    if (opts.scanId && opts.cookieJar !== false && opts.url) {
      try {
        this.jarFor(opts.scanId).mergeInto(headers, opts.url);
      } catch { /* jar 合并失败不阻断请求 */ }
    }
    // [P2-4] Digest 缓存 challenge 预附加：已持有 state 时发送前即带 Authorization（nc 单调递增），
    // 避免「裸请求先吃一次 401 才用上缓存」的多余往返；无 state 时保持裸请求，
    // 由 401 挑战-重放路径（_after401）建立 state。
    let digestPreAttached = false;
    {
      const da0 = opts.auth ?? defaults.auth ?? null;
      const pre = this._digestAuthHeader(opts.method || 'GET', opts.url, da0);
      if (pre && pre.header && !headers['Authorization'] && !headers['authorization']) {
        headers['Authorization'] = pre.header;
        digestPreAttached = true;
      }
    }
    // [P1-2026-09-14] NTLM 预附加：同主机已握过手（持有 Type2 challenge）时直接带 Type3，
    // 省掉 Type1/Type2 两跳。无 state 时保持裸请求，由 401 握手重放（_after401）建立 state。
    {
      const na0 = opts.auth ?? defaults.auth ?? null;
      const ntlmPre = this._ntlm.preAuthHeader(opts.url, na0);
      if (ntlmPre && !headers['Authorization'] && !headers['authorization']) {
        headers['Authorization'] = ntlmPre;
      }
    }
    return { headers, digestPreAttached };
  }

  /**
   * 单次发送（含手动重定向跟随）：http2=true 走 undici（ALPN 协商 h2/h1.1，目标不支持
   * 自动降级 HTTP/1.1），否则走 axios HTTP/1.1（默认路径零变化）。两条路径同样手动跟随
   * 重定向（逐跳 SSRF 校验 + 跨域剥离凭据头 + 每跳 DNS 钉死，见 _followRedirects/_followRedirectsH2）。
   * DNS 钉死 IP 在派发瞬间重新获取（重试/认证重放不复用上一次的死 IP）。
   */
  async _sendFollowRedirects(opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress) {
    if (opts.http2 === true) {
      return this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft, egress);
    }
    const first = await this._rawRequest(
      { lookup: buildPinnedLookup(opts.url) },
      opts, headers, proxyConf, timeoutMs, disableKA,
    );
    return this._followRedirects(first, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
  }

  // [sqlmap 对标] --null-connection：发送 HEAD 请求（无响应体传输），用于布尔盲注快速判定。
  // 复用 request() 全部安全机制（SSRF 校验 / DNS 钉死 / 限速 / 重试），仅 method 改 HEAD。
  // 返回 { status, headers, data: '' } —— HEAD 响应无 body，data 固定空串。
  async headRequest(url, opts = {}) {
    const res = await this.request({
      ...opts,
      method: 'HEAD',
      url,
      data: undefined, // HEAD 请求无请求体
    });
    return {
      status: res?.status ?? 0,
      headers: res?.headers ?? {},
      data: '', // HEAD 响应无 body
    };
  }
}

// —— 五期拆分（2026-10-01）：阶段方法在原型上按原名挂载（与原类方法同调用风格，this 语义不变）——
HttpClient.prototype.undiciAgentInsecure = undiciAgentInsecure;
HttpClient.prototype.createBucket = createBucket;
HttpClient.prototype.removeBucket = removeBucket;
HttpClient.prototype.removeRequestCount = removeRequestCount;
HttpClient.prototype.jarFor = jarFor;
HttpClient.prototype.clearJar = clearJar;
HttpClient.prototype._captureCookies = _captureCookies;
HttpClient.prototype._evictRequestCounts = _evictRequestCounts;
HttpClient.prototype._sleep = _sleep;
HttpClient.prototype.bucketForRate = bucketForRate;
HttpClient.prototype._rawRequest = _rawRequest;
HttpClient.prototype._finishResponse = _finishResponse;
HttpClient.prototype._followRedirects = _followRedirects;
HttpClient.prototype._rawUndici = _rawUndici;
HttpClient.prototype._followRedirectsH2 = _followRedirectsH2;
HttpClient.prototype._digestAuthHeader = _digestAuthHeader;
HttpClient.prototype._digestReplay = _digestReplay;
HttpClient.prototype._setDigestChallenge = _setDigestChallenge;
HttpClient.prototype._assertEgressAllowed = _assertEgressAllowed;
HttpClient.prototype._resolveRateBucket = _resolveRateBucket;
HttpClient.prototype._beforeAttempt = _beforeAttempt;
HttpClient.prototype._after401 = _after401;
HttpClient.prototype._onRequestError = _onRequestError;

export const httpClient = new HttpClient();
export default httpClient;

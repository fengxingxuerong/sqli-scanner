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

import axios from 'axios';
// [P0-SEC 2026-09-08] 逐跳授权范围校验（scope）：目标 302 到圈外主机时，后续全部注入请求
// （含 Cookie/Authorization）会跟着跑出去，只在 API 入口校一次拦不住。scope 按 scanId 登记。
import { getScopeForScan, assertInScope } from './scopeGuard.js';
import http from 'node:http';
import https from 'node:https';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { URL } from 'url';
import { Agent as UndiciAgent, request as undiciRequest } from 'undici';
import { defaults } from '../config/defaults.js';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';
import { CookieJar } from './cookieJar.js';
import { parseDigestChallenge, extractDigestChallenge, buildDigestHeader, makeCnonce } from './digestAuth.js';
// [P1-2026-09-14] NTLM 三步握手（对标 sqlmap --auth-type=NTLM）：Type1 → Type2(challenge) → Type3
import { NtlmHandshake } from './ntlmHandshake.js';
// [大文件二期拆分 2026-09-14] SSRF/代理/一次性日志已抽至 core/http/ 下独立模块；
// 下方 re-export 保证既有 import 路径不变（外部模块与测试仍可从 httpClient.js 取到这些符号）。
import {
  isBlockedIp, resolveHost, buildPinnedLookup, clearHostPin,
  assertSafeHttpTarget, assertSafeTargetForEgress, dnsCache,
  noteEgressIpFailure, IP_FAIL_CODES,
} from './http/egressGuard.js';
import {
  parseProxyUrl, assertProxyUsable, isLocalOrPrivateHost, isNoProxyHost, resolveProxy,
  SOCKS_PROXY_SCHEMES,
} from './http/proxy.js';
import { logOnce, warnInsecureTls } from './http/logOnce.js';
// [大文件二期拆分 2026-09-20] 重定向的纯决策逻辑（跨域判定 / 方法降级 / 凭据头剥离）：
// H1 与 H2 两条跟随路径共用同一份安全语义，且可脱离 I/O 直接单测。
import {
  isCrossOriginRedirect,
  resolveRedirectMethod,
  applyRedirectHeaders,
} from './http/redirectPolicy.js';
// 注：dnsCache / EXTRACT_MAX_BODY_BYTES 等由文件尾部原有 export 语句导出，此处不重复导出。
// 下面这行是**兼容再导出**：这些符号虽已搬走，但既有调用方（含测试）仍从 httpClient.js 取，
// 保持路径不变 = 拆分对调用方零影响（netErrGuard.test.js 就依赖 resolveProxy/isLocalOrPrivateHost）。
export {
  assertSafeHttpTarget, assertSafeTargetForEgress, isBlockedIp, resolveHost,
  assertProxyUsable, isLocalOrPrivateHost, isNoProxyHost, resolveProxy,
  noteEgressIpFailure,
};


// ── [P0-SEC 2026-09-08] 逐跳授权范围（scope）校验 ────────────────────────────────
// 为什么必须在这里而不是只在 API 入口：目标 302 到未授权主机很常见（统一登录跳转、CDN 回源、
// 灰度切流），而扫描器会跟着跳并把后续全部注入请求（含 Cookie/Authorization）打到新主机上。
// 只在 /scan/start 校一次 = 圈外主机被当成圈内目标打完且无人知情，属事故级缺口。
// scope 按 scanId 登记在 scopeGuard（见 registerScanScope），未登记时恒为放行（零行为变化）。
/**
 * @param {string|undefined} scanId 扫描级上下文带 scanId（forScan 注入）；无则不校验
 * @param {string} urlString 本次即将出站的 URL（含重定向后的每一跳）
 */
async function assertScanScope(scanId, urlString) {
  if (!scanId || !urlString) return;
  const scope = getScopeForScan(scanId);
  if (!scope) return;
  assertInScope(String(urlString), scope);
}

// ── [P1-FIX 2026-09-08 ①] TLS 校验开关的 Agent 组合缓存 ────────────────────────
// KEEPALIVE_AGENT_OPTS / httpAgent / httpsAgent 是模块级共享（服务所有扫描）：把
// rejectUnauthorized:false 挂到共享 httpsAgent 上，等于「一个自签目标关掉了全局证书校验」。
// 故按 {insecure, keepAlive} 组合另建 Agent 并缓存复用；默认组合（secure + keepAlive）仍复用
// 原共享实例（零行为变化），undici 侧另有 per-client 不安全 Agent（见 HttpClient.undiciAgentInsecure）。
const _tlsAgentCache = new Map();

/**
 * 取（或惰性建立）指定 TLS/keepAlive 组合的 axios Agent 对。
 * @param {boolean} insecureTls true=关闭证书校验（自签/内网 CA 目标）
 * @param {boolean} [keepAlive] 是否挂 keep-alive（对齐 disableKeepAlive 语义）
 * @returns {{httpAgent?:object, httpsAgent?:object}}
 */
export function agentsForTls(insecureTls, keepAlive = true) {
  const key = `${insecureTls ? 'insecure' : 'secure'}|${keepAlive ? 'ka' : 'noka'}`;
  const hit = _tlsAgentCache.get(key);
  if (hit) return hit;
  /** @type {any} */ let conf;
  if (!insecureTls) conf = keepAlive ? { httpAgent, httpsAgent } : {};
  else {
    const base = keepAlive ? { ...KEEPALIVE_AGENT_OPTS } : { keepAlive: false, maxSockets: AGENT_MAX_SOCKETS };
    conf = {
      httpAgent: new http.Agent(base),
      // 只有 https Agent 需要关校验（http 通道无 TLS）
      httpsAgent: new https.Agent({ ...base, rejectUnauthorized: false }),
    };
  }
  _tlsAgentCache.set(key, conf);
  return conf;
}

/**
 * [P1-FIX ①] 给「代理 Agent」注入 rejectUnauthorized:false。
 * 为什么只换 httpsAgent 不够：socks 路径下 axios 把 options.agent 指向代理 Agent，TLS 升级发生在
 * socks-proxy-agent 内部（tls.connect({...请求级 options})），而 axios 不透传未知配置键 →
 * 请求级 rejectUnauthorized 到不了那里。addRequest 是唯一能碰到请求级 options 的入口，在此拦一层，
 * 只对「经本 Agent 发出的请求」关闭校验，不改任何全局配置。
 * @param {object} agent 代理 Agent 实例
 * @returns {object} 同一实例（便于链式）
 */
function markAgentInsecure(agent) {
  try {
    const orig = agent.addRequest.bind(agent);
    agent.addRequest = function addRequestInsecure(req, options, ...rest) {
      // Node 新版签名 (req, options)；旧版 (req, port, host) → 仅对象时注入
      if (options && typeof options === 'object') {
        try {
          options.rejectUnauthorized = false;
        } catch { /* 冻结对象：忽略，最差退化为「证书校验仍开启」 */ }
      }
      return orig(req, options, ...rest);
    };
  } catch { /* 注入失败不致命 */ }
  return agent;
}

/**
 * [P1-FIX 2026-09-08 ③] 响应体字符集解码
 * 旧实现 responseType:'text' → axios 无条件按 utf8 解码：GBK/Big5/Shift-JIS/EUC-KR/Windows-1252
 * 目标（老 Java/ASP/JSP 站极常见）被解成 U+FFFD 且不可逆 —— 中文报错文案丢失、布尔比对出现字节
 * 碰撞（不同字节序列映射成同一替换符 → 差异消失 → 漏检）、拖库出的中文数据是乱码。
 * 现在两条通道统一先取原始字节、再按声明字符集解码，对外仍是 string。
 */
import {
  decompressResponseBody,
  decodeResponseBody,
  attachResMeta,
  getResponseHeader,
  finalizeAxiosResponse,
} from './http/responseCodec.js';
// 再导出：既有 import 路径保持不变（外部模块与测试仍可从 httpClient.js 取到这些符号）
export {
  decompressResponseBody,
  detectResponseCharset,
  decodeResponseBody,
  getResMeta,
  attachResMeta,
} from './http/responseCodec.js';
import {
  AGENT_MAX_SOCKETS,
  TLS_CERT_CODES,
  isMaxContentLengthError,
} from './http/agentPool.js';
// 再导出：既有 import 路径保持不变（外部模块与测试仍可从 httpClient.js 取到这些符号）
export {
  computeAgentMaxSockets,
  AGENT_MAX_SOCKETS,
} from './http/agentPool.js';
const KEEPALIVE_AGENT_OPTS = {
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxSockets: AGENT_MAX_SOCKETS,
  maxFreeSockets: Math.min(10, AGENT_MAX_SOCKETS),
  timeout: 30000,
  freeSocketTimeout: 15000,
};
const httpAgent = new http.Agent(KEEPALIVE_AGENT_OPTS);
const httpsAgent = new https.Agent(KEEPALIVE_AGENT_OPTS);

// 不可重试的错误码（原逻辑不变）
const NON_RETRYABLE_CODES = new Set([
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
const MAX_BODY_BYTES = (() => {
  const mb = Number(process.env.SSRF_MAX_BODY_MB) || 10;
  return Math.max(1, mb) * 1024 * 1024;
})();
const EXTRACT_MAX_BODY_BYTES = (() => {
  const mb = Number(process.env.EXTRACT_MAX_BODY_MB) || 50;
  return Math.max(1, mb) * 1024 * 1024;
})();
// --delay 单次延时上限（秒）：防止把毫秒值当秒传入导致请求长时间挂起
const MAX_DELAY_SEC = 60;
// --max-requests 计数表最大条目数：超出后清理最早写入的条目，防异常退出残留累积
const MAX_TRACKED_SCANS = 512;

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

// [P0-FIX] SOCKS/HTTP 代理 Agent 模块级缓存（按 proxyUrl 复用），避免每次请求重建 Agent
// 造成的 TCP+SOCKS5 握手开销（高量盲注提取下为主导成本）。
const _proxyAgentCache = new Map();

/**
 * 根据 proxyUrl 构建（或从缓存复用）代理 Agent 配置。
 * 支持 socks5/socks5h/socks4/socks4a（交给 SocksProxyAgent）与 http/https（交给 axios 原生 proxy）；
 * 按 proxyUrl + 是否关闭证书校验缓存，以复用 keepAlive 长连接。
 * @param {string} [proxyUrl] 代理 URL
 * @param {{insecureTls?:boolean}} [opts] insecureTls=true 时为代理 Agent 注入 rejectUnauthorized:false
 * @returns {{proxy:boolean|object, httpAgent?:object, httpsAgent?:object}} axios 代理配置
 */
export function buildProxyAgent(proxyUrl, { insecureTls = false } = {}) {
  if (!proxyUrl) return { proxy: false };
  // 命中缓存：复用已创建的 Agent（keepAlive 长连接复用）。insecure/secure 必须分 key——
  // 否则「先安全后不安全」的进程会复用严格校验的 Agent（自签目标照旧连不上）。
  const cacheKey = `${proxyUrl}|${insecureTls ? 'insecure' : 'secure'}`;
  if (_proxyAgentCache.has(cacheKey)) return _proxyAgentCache.get(cacheKey);
  const { u, scheme } = parseProxyUrl(proxyUrl);
  /** @type {any} */ let conf;
  if (SOCKS_PROXY_SCHEMES.has(scheme)) {
    // [P1-FIX ②] 旧实现只认 ^socks5?://，socks4:// 与 socks4a:// 落到 else 分支被当成 http 明文
    // 代理发出（凭据泄漏）。现按 socks-proxy-agent 支持的完整 scheme 集合分流（类型/是否本地解析
    // 由该库按 scheme 自行决定），SOCKS 与 TLS 选项互斥路径也不再混用。
    const agent = new SocksProxyAgent(proxyUrl, { keepAlive: true, maxSockets: AGENT_MAX_SOCKETS });
    if (insecureTls) markAgentInsecure(agent);
    conf = { proxy: false, httpAgent: agent, httpsAgent: agent };
  } else {
    conf = {
      proxy: {
        protocol: scheme,
        host: u.hostname,
        // 无端口时补默认端口：旧实现 Number('') → NaN 直连失败，而环境变量代理常省略端口
        port: Number(u.port) || (scheme === 'https' ? 443 : 80),
      },
    };
    // [P2-FIX 2026-09-05] HTTP 代理 URL 内嵌凭据（http://user:pass@host:port）不再丢失：
    // 旧实现只取 protocol/host/port 丢弃 user:pass@，导致带认证的代理 407 拒连。
    // 填入 axios proxy.auth（{username,password}）由其生成 Proxy-Authorization: Basic。
    if (u.username || u.password) {
      conf.proxy.auth = {
        username: decodeURIComponent(u.username),
        password: decodeURIComponent(u.password || ''),
      };
    }
    // [P1-FIX ①] http 代理 + https 目标时，axios 会自建 CONNECT 隧道 Agent，并只从
    // config.httpsAgent.options 继承 TLS 选项 → 必须把 insecure httpsAgent 一并传下去，
    // 否则隧道仍按默认严格校验（Burp + 自签内网目标照旧握手失败）。
    if (insecureTls) conf.httpsAgent = agentsForTls(true, true).httpsAgent;
  }
  // 缓存上限：防止异常配置导致无界增长
  if (_proxyAgentCache.size > 16) _proxyAgentCache.delete(_proxyAgentCache.keys().next().value);
  _proxyAgentCache.set(cacheKey, conf);
  return conf;
}

const BACKOFF_BASE_MS = 100;
const BACKOFF_MAX_MS = 1000;

async function applyJitter(wafEvasion) {
  if (wafEvasion && wafEvasion.jitterMs > 0) {
    const ms = Math.floor(Math.random() * wafEvasion.jitterMs);
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}

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

  // [P1-FIX ①] insecureTls 专用 Agent：connect.rejectUnauthorized:false（undici 的 TLS 选项在
  // connect 上，而不是 Agent 顶层），与默认 Agent 分开持有，避免关掉共享 Agent 的证书校验。
  undiciAgentInsecure() {
    if (!this._undiciAgentInsecure) {
      this._undiciAgentInsecure = new UndiciAgent({
        connect: { timeout: defaults.timeoutMs, rejectUnauthorized: false },
        connections: AGENT_MAX_SOCKETS,
        pipelining: 1,
      });
    }
    return this._undiciAgentInsecure;
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

  createBucket(scanId, ratePerSec) {
    // [P0-FIX 2026-09-14] ratePerSec<=0 = 不限速：建 UNLIMITED 桶（TokenBucket 内部处理），
    // 保持 per-scan 桶注册表结构不变（removeBucket/桶查询路径零改动）。原实现把 <=0 换成
    // defaults —— 显式 0 的调用方（本地靶场「不限速」意图）被暗中按保守默认限速。
    const rps = Number.isFinite(ratePerSec) && ratePerSec > 0 ? ratePerSec : 0;
    const bucket = new TokenBucket(rps);
    this.buckets.set(scanId, bucket);
    return bucket;
  }

  removeBucket(scanId) {
    this.buckets.delete(scanId);
  }

  // [sqlmap 对标] --max-requests：清理 scanId 的请求计数（扫描结束时调用）
  removeRequestCount(scanId) {
    this._requestCounts.delete(scanId);
  }

  // [P1-FIX 2026-09-05] Cookie Jar：按 scanId 惰性创建；clearJar 随扫描退役调用
  jarFor(scanId) {
    if (!this._jars.has(scanId)) this._jars.set(scanId, new CookieJar());
    return this._jars.get(scanId);
  }

  clearJar(scanId) {
    this._jars.delete(scanId);
  }

  // 捕获响应 Set-Cookie 入 jar（幂等；cookieJar=false / dropSetCookie=true 时跳过，
  // 后者对标 --drop-set-cookie）
  _captureCookies(url, res, opts) {
    if (!opts || !opts.scanId || opts.cookieJar === false || opts.dropSetCookie === true) return;
    const setCookies = res && res.headers && res.headers['set-cookie'];
    if (!setCookies) return;
    try {
      this.jarFor(opts.scanId).setFromResponse(url, setCookies);
    } catch { /* cookie 解析失败不影响请求主流程 */ }
  }

  // 计数表兜底清理：条目超上限时按 Map 插入顺序（最早写入）淘汰。
  // 正常路径由 removeRequestCount 回收；异常退出/未挂 scanId 的路径才依赖此处。
  _evictRequestCounts() {
    if (this._requestCounts.size <= MAX_TRACKED_SCANS) return;
    const overflow = this._requestCounts.size - MAX_TRACKED_SCANS;
    let n = 0;
    for (const key of this._requestCounts.keys()) {
      if (n++ >= overflow) break;
      this._requestCounts.delete(key);
    }
  }

  // 可中断延时：delay 期间若扫描被停止（signal aborted）立即返回，不必等完整个周期
  _sleep(ms, signal) {
    if (!ms || ms <= 0) return Promise.resolve();
    return new Promise(/** @param {(value?: any) => void} resolve */ (resolve) => {
      const timer = setTimeout(() => {
        if (signal) signal.removeEventListener?.('abort', onAbort);
        resolve();
      }, ms);
      function onAbort() {
        clearTimeout(timer);
        resolve();
      }
      if (signal) {
        if (signal.aborted) { clearTimeout(timer); return resolve(); }
        signal.addEventListener?.('abort', onAbort, { once: true });
      }
    });
  }

  bucketForRate(ratePerSec) {
    // [P0-FIX 2026-09-14] 调用方保证只在 effectiveRate>0 时进入本方法；<=0 守卫为直通语义
    // 由上层处理（主选择点已短路），这里保留 >0 归一防误用。
    const rps = Number.isFinite(ratePerSec) && ratePerSec > 0 ? ratePerSec : defaults.ratePerSec;
    if (!this.rateBuckets.has(rps)) {
      // [P0-FIX] 兜底淘汰：rate 值由调用方控制（ratePerSec 透传），恶意/异常值可撑爆 Map。
      // 正常路径下 per-scan 限速走 createBucket/removeBucket；此处仅服务无 scanId 的请求。
      if (this.rateBuckets.size >= MAX_TRACKED_SCANS) {
        this.rateBuckets.delete(this.rateBuckets.keys().next().value);
      }
      this.rateBuckets.set(rps, new TokenBucket(rps));
    }
    return this.rateBuckets.get(rps);
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

  // 单跳请求（已通过 SSRF 校验的 URL）
  async _rawRequest(cfg, opts, headers, proxyConf, timeoutMs, disableKA) {
    // [P0-FIX] 提取路径（opts.maxContentLength）动态放大响应上限：默认 10MB，提取可至 50MB
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    const insecureTls = effectiveInsecureTls(opts);
    // [P1-FIX ①] 传输层 Agent 选择（insecureTls 与 disableKeepAlive 交叉）：
    //   · 代理自带 Agent（socks）→ 保留代理 Agent（证书校验由 markAgentInsecure 注入，不另挂 Agent）
    //   · insecureTls → 换用专用 insecure Agent（keepAlive 跟随 disableKA），绝不改共享 Agent 实例
    //   · 其余 → 沿用 instance 默认；disableKA 时回退 Node 默认 Agent（保持历史语义）
    const transport = proxyConf.httpAgent
      ? {}
      : insecureTls
        ? agentsForTls(true, !disableKA)
        : disableKA
          ? { httpAgent: false, httpsAgent: false }
          : {};
    const res = await this.instance.request({
      method: opts.method || 'GET',
      url: opts.url,
      params: opts.params,
      data: opts.data,
      headers,
      timeout: timeoutMs,
      maxContentLength: maxBody,
      maxBodyLength: maxBody,
      ...proxyConf,
      ...transport,
      maxRedirects: 0,
      // [P1-FIX 2026-09-08 ③] 响应体取原始字节（arraybuffer），由本类按声明字符集解码后再赋回
      // res.data —— 旧值 'text' 让 axios 无条件按 utf8 解码，GBK/Big5/Shift-JIS/EUC-KR 目标不可逆地
      // 变 U+FFFD（中文报错文案丢失 + 布尔比对字节碰撞漏检 + 拖库中文乱码）。
      // 另一层不变的原因：不能省掉 responseType（axios 默认按 Content-Type 自动 JSON.parse →
      // res.data 变对象/数组，检测器 String(res.data) 得到 "[object Object]"/""，JSON API 上的
      // 布尔真假判定语义全失 → 恒漏检），解码后契约仍是 string，与 undici 通道一致。
      responseType: 'arraybuffer',
      // 配套跳过 axios 的隐式响应转换（双保险，防止默认 transformResponse 再解析）
      transformResponse: [(d) => d],
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...cfg,
    });
    return this._finishResponse(res, opts);
  }

  // [P1-FIX ③④] axios 通道响应后处理：解码文本（对外仍是 string）+ 挂 __meta 元数据。
  // 超限在 axios 侧是「抛错」而非截断（maxContentLength 命中即 reject），故 truncated 恒 false；
  // 真正的静默截断风险在 undici 通道（见 _rawUndici），两通道共用同一元数据契约。
  // [大文件二期拆分 2026-09-20] 逻辑已外移至 http/responseCodec.js#finalizeAxiosResponse
  // （纯函数、无 this 依赖）。此处保留同名方法作为薄委托：方法名不动 = 既有调用方与
  // 打桩测试零影响，行为与原实现逐字节一致。
  _finishResponse(res, opts) {
    return finalizeAxiosResponse(res, opts);
  }

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
  async _followRedirects(initial, opts, headers, proxyConf, timeoutMs, disableKA, redirects, egress = null) {
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

  // [HTTP/2] undici 传输层（对标 sqlmap --http2）：HTTP/2 + HTTP/1.1 ALPN 协商，
  // 单连接多路复用对批量请求（爬虫取页 / 常用标量提取）有吞吐收益。
  // 返回与 axios 响应同构的 { status, data, headers }；SSRF 校验已在 request() 入口完成。
  // [P1-FIX ①] insecureTls 时改用专用 undici Agent（connect.rejectUnauthorized:false），
  // 不复用 this.undiciAgent —— 后者是 per-client 共享给「校验开启」流量的，关掉它等于全局裸奔。
  // [P1-FIX ③④] 与 axios 通道共用 decodeResponseBody + __meta（超限不再只留一行文本）。
  async _rawUndici(opts, headers, timeoutMs, pinnedLookup) {
    const insecureTls = effectiveInsecureTls(opts);
    const dispatcher = insecureTls ? this.undiciAgentInsecure() : this.undiciAgent;
    // DNS 钉死：优先用已校验 IP（防 rebinding）；无法钉死时回退常规解析（undici 自行解析）
    let lookup;
    if (pinnedLookup) {
      lookup = (hostname, o, cb) => pinnedLookup(hostname, o, cb);
    }
    const connectOpts = { ...(/** @type {any} */ (dispatcher).opts?.connect || {}) };
    if (insecureTls) connectOpts.rejectUnauthorized = false;
    if (lookup) connectOpts.lookup = lookup;
    const { statusCode, headers: resHeaders, body } = await undiciRequest(opts.url, {
      dispatcher,
      method: String(opts.method || 'GET'),
      headers: { ...headers },
      body: opts.data,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      connect: connectOpts,
      ...(opts.signal ? { signal: opts.signal } : {}),
      // [P0-FIX] 手动重定向（逐跳 SSRF 校验 + 跨域剥离敏感头由 _followRedirectsH2 负责）：
      // undici 内置 maxRedirections 跟随的跳转目标不经过 assertSafeHttpTarget 校验、不钉 DNS，
      // 302 可跳内网/元数据地址（绕过出口 SSRF 防护）。置 0 关闭内置跟随。
      // @ts-expect-error undici 支持 maxRedirections，但其 RequestOptions 类型未收录（运行时有效）
      maxRedirections: 0,
    });
    // 体积上限：读流但截断超限（与 axios maxContentLength 语义近似，防 OOM）
    const chunks = [];
    let total = 0;
    let truncated = false;
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    for await (const chunk of body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += b.length;
      if (total > maxBody) {
        // [P1-FIX ④] 不再把「截断说明」混进 body 就返回：检测器只看 data/status，
        // 截断会被当成「内容不同/相同」。这里保留同样的提示文本（位置不变），并额外挂
        // __meta.truncated + warn 一次，让上层/报告可判定「本次比对不可信」。
        truncated = true;
        break;
      }
      chunks.push(b);
    }
    let raw = Buffer.concat(chunks);
    // [P0-FIX 2026-09-09] undici 通道不自动解压（axios 会）。目标或前置代理返回 gzip/deflate/br 时，
    // 原实现把压缩字节当文本解码 → 整页 U+FFFD，检测器看到的是「内容差异巨大」，于是
    // `--http2` 与默认通道对同一目标给出相反结论（一边正常、一边全盲）。这里补齐，失败则显式标注。
    const enc = getResponseHeader(resHeaders, 'content-encoding');
    let encodingUnsupported = false;
    if (enc && enc !== 'identity' && !truncated) {
      try {
        raw = /** @type {any} */ (decompressResponseBody(raw, enc));
      } catch (e) {
        encodingUnsupported = true;
        logger.warn(
          `响应 content-encoding=${enc} 解压失败（${e.message}）：本次响应未按解压结果使用，` +
            '该点差异比对不可信。建议关闭 http2（走 axios 通道）或确认代理未改写编码头'
        );
      }
    }
    const decoded = decodeResponseBody(raw, resHeaders);
    let text = decoded.text;
    if (truncated) text += `[响应超限截断 ${total} 字节 > ${maxBody}]`;
    const res = { status: statusCode, data: text, headers: resHeaders, isHttp2: true };
    if (truncated) {
      logOnce(
        'warn',
        `响应体超限已截断（${total} 字节 > ${maxBody} 字节）：${logSafeUrl(opts.url || '')}。` +
          `差异比对可能失真（漏检风险），请调高 SSRF_MAX_BODY_MB（当前 ${Math.round(MAX_BODY_BYTES / 1048576)}MB）`
      );
    }
    attachResMeta(res, {
      bodyBytes: raw.length,
      truncated,
      charset: decoded.charset,
      charsetSource: decoded.charsetSource,
      ...(decoded.charsetUnsupported
        ? { charsetUnsupported: true, declaredCharset: decoded.declaredCharset }
        : {}),
      ...(encodingUnsupported ? { contentEncodingUnsupported: true, contentEncoding: enc } : {}),
    });
    return res;
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
  async _followRedirectsH2(opts, headers, timeoutMs, redirects, egress = null) {
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

  // ===== [P2-4] Digest 认证（对标 sqlmap --auth-type=Digest） =====
  // 状态模型：_digestStates 按 hostKey(protocol+host) 缓存 { challenge, nc, username, cnonce }。
  //   · 首个请求（无缓存 challenge）→ 发裸请求；收到 401+Digest 挑战 → 建 state → 重放一次。
  //   · 缓存复用 → nc 每次单调递增（服务端防重放计数校验）。
  //   · 服务端 nonce 过期再返 401 → 刷新 challenge 重建 state（防死循环：仅允许挑战-重放一轮）。

  // 尝试构造 Digest Authorization 头。
  // @returns {null} 无 digest 配置 | { header } 可直用 | { needChallenge:true, hostKey, cred, uri } 需先裸请求
  _digestAuthHeader(method, url, auth) {
    if (!auth || typeof auth !== 'object') return null;
    const cred = auth.digest || (auth.type && String(auth.type).toLowerCase() === 'digest' ? auth.basic : null);
    if (!cred || cred.username == null) return null;
    let u;
    try { u = new URL(url); } catch { return null; }
    const hostKey = u.protocol + '//' + u.host;
    const uri = u.pathname + u.search;
    const state = this._digestStates.get(hostKey);
    if (state && state.username === cred.username) {
      const nc = state.nc + 1;
      state.nc = nc;
      const header = buildDigestHeader({
        method, uri,
        challenge: state.challenge,
        username: cred.username,
        password: cred.password != null ? cred.password : '',
        nc, cnonce: state.cnonce,
      });
      return { header };
    }
    return { needChallenge: true, hostKey, cred, uri };
  }

  // 401 + WWW-Authenticate: Digest → 建 state 并返回重放头
  // @returns {replay:false} | {replay:true, header}
  _digestReplay(method, url, auth, res) {
    if (!res || res.status !== 401) return { replay: false };
    if (!auth || typeof auth !== 'object') return { replay: false };
    const cred = auth.digest || (auth.type && String(auth.type).toLowerCase() === 'digest' ? auth.basic : null);
    if (!cred || cred.username == null) return { replay: false };
    const ch = extractDigestChallenge(res.headers);
    if (!ch) return { replay: false };
    let u;
    try { u = new URL(url); } catch { return { replay: false }; }
    const hostKey = u.protocol + '//' + u.host;
    const cnonce = makeCnonce();
    if (!this._setDigestChallenge(hostKey, cred, res.headers['www-authenticate'], cnonce)) {
      return { replay: false };
    }
    const state = this._digestStates.get(hostKey);
    state.nc = 1;
    const header = buildDigestHeader({
      method, uri: u.pathname + u.search,
      challenge: state.challenge,
      username: cred.username,
      password: cred.password != null ? cred.password : '',
      nc: 1, cnonce,
    });
    return { replay: true, header };
  }

  _setDigestChallenge(hostKey, cred, challengeHeader, cnonce) {
    const challenge = parseDigestChallenge(challengeHeader);
    if (!challenge) return false;
    this._digestStates.set(hostKey, { challenge, nc: 0, cnonce: cnonce || makeCnonce(), username: cred.username });
    return true;
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
    // P0-1：出口统一 SSRF 校验（直连模式 req.sql 无 URL，跳过）
    // [P1-FIX ②] 已走代理且 ssrfViaProxy!=='off' → 解析/严格层判定下放至代理（硬底线段仍无条件拒）
    if (opts.url) {
      await assertSafeTargetForEgress(opts.url, egress).catch((e) => {
        if (e instanceof AppError) throw e;
        throw new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
      });
      // [P0-SEC] 授权范围（scope）逐请求校验：目标 URL 在 start 时校过，但爬虫/二阶/safeUrl/
      // 手工构造的注入请求都可能指向另一个主机，统一在出口拦一次。
      await assertScanScope(opts.scanId, opts.url);
    }

    // [P0-3] DNS 钉死：从缓存取已校验 IP，传给请求层避免二次解析（防 DNS rebinding）
    // 仅在 assertSafeHttpTarget 已成功校验过该 URL 时生效
    // [P0-FIX 2026-09-09] 逐次尝试重新取钉死 IP（原实现整条请求只算一次，重试必然又打同一个死 IP）。
    const pinnedLookup = () => buildPinnedLookup(opts.url);
    // [P2-5] --ignore-redirects：跟随上限置 0 → 3xx 直接返回不跳转
    const redirectsLeft = opts.ignoreRedirects === true ? 0 : 5;
    // [sqlmap 对标] --reqrate：reqRate > 0 时覆盖 ratePerSec 作为 TokenBucket 速率
    const effectiveRate = (opts.reqRate && opts.reqRate > 0) ? opts.reqRate : opts.ratePerSec;
    // [P0-FIX 2026-09-14] 限速语义对齐 TokenBucket：effectiveRate<=0 = 不限速（直通，不落桶）。
    // 原实现把 <=0 交给 this.bucket（defaults 单例桶），显式 0 会被暗中按默认值限速——
    // defaults 保守化后该错位直接打崩以 0 表达「不限速」的调用方（pentest-lab 实测 0/10）。
    const bucket =
      (opts.scanId && this.buckets.get(opts.scanId)) ||
      (Number.isFinite(effectiveRate) && effectiveRate > 0
        ? this.bucketForRate(effectiveRate)
        : Number.isFinite(effectiveRate) && effectiveRate <= 0
          ? null // 不限速：跳过令牌桶
          : this.bucket); // 未配置 → 默认单例桶（defaults.ratePerSec）
    // [P1-FIX ①②] 代理来源已在入口统一解析（含环境变量），insecureTls 一并决定 Agent 组合
    const proxyConf = buildProxyAgent(/** @type {string} */ (proxyUrl), { insecureTls });
    const disableKA = opts.disableKeepAlive === true || this.disableKeepAlive === true;
    // 头合并（含 P2-8 头名黑名单过滤）
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
    // 由下方 401 挑战-重放路径建立 state。用户显式 Authorization 优先，不干预。
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
    // 省掉 Type1/Type2 两跳。无 state 时保持裸请求，由下方 401 握手重放建立 state。
    {
      const na0 = opts.auth ?? defaults.auth ?? null;
      const ntlmPre = this._ntlm.preAuthHeader(opts.url, na0);
      if (ntlmPre && !headers['Authorization'] && !headers['authorization']) {
        headers['Authorization'] = ntlmPre;
      }
    }
    let lastErr;
    for (let attempt = 0; attempt <= retry; attempt++) {
      // [⑮] abort 检查：signal 已取消时不再发新请求（重试循环防漏）
      if (opts.signal?.aborted) {
        const abortErr = /** @type {NodeJS.ErrnoException} */ (new Error('请求已取消（扫描停止）'));
        abortErr.name = 'AbortError';
        abortErr.code = 'ERR_CANCELED';
        throw abortErr;
      }
      // [sqlmap 对标] --max-requests：请求计数检查，达上限后拒绝新请求。
      // 仅对归属明确（带 scanId）的请求计数：无 scanId 的请求无法在扫描结束时回收计数，
      // 用统一 key 会导致 ① Map 无界增长 ② 达到上限后全局永久拒绝新请求（不可恢复）。
      if (opts.maxReq && opts.maxReq > 0 && opts.scanId) {
        const count = this._requestCounts.get(opts.scanId) || 0;
        if (count >= opts.maxReq) {
          throw new AppError(ErrorCode.HTTP_ERROR, `请求上限已达（maxReq=${opts.maxReq}），拒绝新请求`);
        }
        this._requestCounts.set(opts.scanId, count + 1);
        this._evictRequestCounts(); // 兜底：防止异常退出残留的 scanId 条目累积
      }
      // [sqlmap 对标] --delay：每次请求前固定延时（秒），降低请求速率。
      // 上限 60s 防误配（如把毫秒当秒传入导致请求挂起）；延时期间响应 abort signal，
      // 避免「点了停止却要等完一个 delay 周期才生效」。
      if (opts.delay > 0) {
        await this._sleep(Math.min(Number(opts.delay) || 0, MAX_DELAY_SEC) * 1000, opts.signal);
        // [P2-FIX] delay 期间可能被 abort（_sleep 响应 signal 提前返回），
        // 复查 signal：已取消则不再发请求（原实现 sleep 后直接继续，浪费一次请求）
        if (opts.signal?.aborted) {
          const abortErr = /** @type {NodeJS.ErrnoException} */ (new Error('请求已取消（扫描停止）'));
          abortErr.name = 'AbortError';
          abortErr.code = 'ERR_CANCELED';
          throw abortErr;
        }
      }
      try {
        await bucket?.acquire(); // [P0-FIX 2026-09-14] bucket 可为 null（不限速直通）
        await applyJitter(opts.wafEvasion);
        // networkTiming（MERGED: perf 版）：从「令牌获取完成之后」计网络耗时，供时间盲注判定
        // 剔除限速排队等待（限速低时并发采样的排队时间会被旧 __elapsed 计入，导致基线虚高）。
        const t0Net = opts.networkTiming === true ? performance.now() : null;
        // [HTTP/2] 开启时走 undici（ALPN 协商 h2/h1.1）；否则沿用 axios HTTP/1.1（默认路径零变化）。
        // HTTP/2 路径同样手动跟随重定向（逐跳 SSRF 校验 + 跨域剥离凭据头，见 _followRedirectsH2）。
        let res;
        if (opts.http2 === true) {
          res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft, egress);
        } else {
          const first = await this._rawRequest({ lookup: pinnedLookup() }, opts, headers, proxyConf, timeoutMs, disableKA);
          res = await this._followRedirects(first, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
        }
        // [P2-4] Digest 挑战-重放：请求未显式带 Authorization 且收到 401+Digest challenge →
        // 本轮构造响应头并重发一次（对标 curl --digest 的 challenge→response 往返）。
        // ① 预附加的缓存 Digest 头被 401 拒绝 → 清 state，下次请求重新挑战（nonce 过期自愈）；
        // ② 用户显式 Authorization（Basic/Bearer/自定义）→ 不干预；
        // ③ digest 配置缺失 / 非 401 / 无 Digest challenge → 不干预；
        // ④ 重发仍 401 → 返回该响应（凭据无效，语义与普通 401 一致，不死循环）。
        if (res && res.status === 401 && digestPreAttached) {
          // [P2-4] 服务端拒绝缓存的 Digest 凭据（nonce 过期/凭据变更）→ 清 state，下次请求重新挑战
          try { this._digestStates.delete(new URL(opts.url).protocol + '//' + new URL(opts.url).host); } catch { /* ignore */ }
        } else if (res && res.status === 401 && !headers['Authorization'] && !headers['authorization']) {
          const da = opts.auth ?? defaults.auth ?? null;
          if (da && typeof da === 'object') {
            const need = this._digestAuthHeader(opts.method || 'GET', opts.url, da);
            if (need && need.needChallenge) {
              // 无缓存 challenge：首次裸请求返回 401 → 建立 state 并重放
              const rp = this._digestReplay(opts.method || 'GET', opts.url, da, res);
              if (rp.replay) {
                headers['Authorization'] = /** @type {string} */ (rp.header);
                if (opts.http2 === true) {
                  res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft, egress);
                } else {
                  const first2 = await this._rawRequest({ lookup: pinnedLookup() }, opts, headers, proxyConf, timeoutMs, disableKA);
                  res = await this._followRedirects(first2, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
                }
                // 重放后仍 401 → 凭据无效/nonce 过期：清 state 防死循环（下次请求重新挑战）
                if (res && res.status === 401 && opts.url) {
                  try { this._digestStates.delete(new URL(opts.url).protocol + '//' + new URL(opts.url).host); } catch { /* ignore */ }
                }
              }
            } else if (need && need.header) {
              // 有缓存 challenge：直接带（mergeAuthHeaders 不处理 digest）
              headers['Authorization'] = need.header;
              if (opts.http2 === true) {
                res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft, egress);
              } else {
                const first2 = await this._rawRequest({ lookup: pinnedLookup() }, opts, headers, proxyConf, timeoutMs, disableKA);
                res = await this._followRedirects(first2, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
              }
            }
          }
        }
        // [P1-2026-09-14] NTLM 三步握手重放：最多 2 跳（Type1 → Type2 → Type3）。
        // 与 Digest 单次重放不同——NTLM 要服务端先回 Type2 才能算 Type3，故这里是**有上限的循环**
        // （hop<2 硬上限，且 done=true 后仍 401 即清 state 退出，双保险防死循环）。
        // 仅当配置了 NTLM 凭据且响应仍是 401+NTLM 挑战时进入；用户显式 Authorization 优先不干预。
        {
          const na = opts.auth ?? defaults.auth ?? null;
          if (res && res.status === 401 && na && typeof na === 'object' && this._ntlm.cred(na)) {
            for (let hop = 0; hop < 2; hop++) {
              const rp = this._ntlm.replay(opts.url, na, res);
              if (!rp.replay || !rp.header) break;
              headers['Authorization'] = rp.header;
              if (opts.http2 === true) {
                res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft, egress);
              } else {
                const first2 = await this._rawRequest({ lookup: pinnedLookup() }, opts, headers, proxyConf, timeoutMs, disableKA);
                res = await this._followRedirects(first2, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft, egress);
              }
              if (!res || res.status !== 401) break; // 认证通过（或其它状态）→ 结束握手
              if (rp.done) {
                // 已发 Type3 仍 401 → 凭据无效：清 state，避免后续请求一直重试坏凭据
                this._ntlm.clear(opts.url);
                break;
              }
            }
          }
        }
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
        // [P0-FIX] AppError（SSRF 拦截 / 参数校验失败）是确定性的安全拒绝，重试多少次结果都一样，
        // 且每次重试都会重放整条重定向链（放大对禁止目标的探测）。必须立即抛出，不进入重试循环。
        if (err instanceof AppError) throw err;
        // [P0-FIX 2026-09-09] 连接层失败 → 拉黑刚用的出口 IP 并前移索引，使**本次重试**就打到另一个节点
        // （CDN/多 A 记录目标里单节点宕机时，不必等整段扫描超时）。超时不计：目标被重载荷拖慢 ≠ 节点死。
        if (err && err.code && IP_FAIL_CODES.has(err.code)) noteEgressIpFailure(opts.url, err.code);
        // [⑮] AbortError/CanceledError：扫描停止触发的请求取消，不重试直接抛出
        if (err.name === 'AbortError' || err.name === 'CanceledError' || err.code === 'ERR_CANCELED' || err.code === 'ABORT_ERR') {
          throw err;
        }
        // [P1-FIX ①] 证书类错误此前只是「快速失败 → 扫不出」，用户无从知道是证书问题；
        // 保留 NON_RETRYABLE 语义（重试无意义），但把逃生口与后果写进日志。
        if (err && err.code && TLS_CERT_CODES.has(err.code)) {
          logger.warn(
            `TLS 证书校验失败（${err.code}）：目标可能使用自签/内网 CA 证书。` +
              '如需扫描此类目标，设 insecureTls=true（关闭证书校验，报告须注明）；' +
              '更推荐把内网根证书加入系统信任链。'
          );
        }
        // [P1-FIX ④] axios 通道超限是「抛错」而非截断：明确记一条，避免被当成普通网络错误
        // 重试耗尽后无痕（提取路径已按 opts.maxContentLength 放大，此处针对扫描主链路）。
        if (isMaxContentLengthError(err)) {
          const limit = opts.maxContentLength ?? MAX_BODY_BYTES;
          logger.warn(
            `响应体超过上限（SSRF_MAX_BODY_MB 当前 ${Math.round(limit / 1048576)}MB）：` +
              `${logSafeUrl(opts.url || '')} 本次请求失败（未截断返回），差异比对在该点上不可用。`
          );
          // [P1-FIX 2026-09-09] 超限不重试：响应体积与重试无关，重试必然得到同一个错误，
          // 但每次都要把响应缓冲到上限再丢弃——在文件下载/大列表页这类目标上，
          // 相当于每个请求白烧 (retry+1) × 上限的内存与带宽（默认 4 × 15MB × 并发），
          // 还会把「目标页面太大」的真因埋进「HTTP 请求失败」。立即失败后，上层（预筛/守卫）
          // 能看到确定性的原因，而不是 4 次同构失败。
          throw new AppError(
            ErrorCode.HTTP_ERROR,
            `响应体超过上限（${Math.round(limit / 1048576)}MB），已快速失败（不重试）：${logSafeUrl(opts.url || '')}`
          );
        }
        const isTimeout = err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '');
        if (err && err.code && NON_RETRYABLE_CODES.has(err.code)) {
          // [P0-FIX 2026-09-09] 区分「整个域名解析不出来」与「某个 IP 拒连」：
          //   • ENOTFOUND/EAI_AGAIN：已校验的 IP 列表来自旧解析结果，可能已整体变更 → 清空缓存 + 清钉死状态；
          //   • ECONNREFUSED：只可能是那一个节点的问题，上面 noteEgressIpFailure 已经拉黑该 IP 并前移索引。
          //     原实现这里直接 dnsCache.delete(hostname) 会把**已校验通过**的 IP 列表一起丢掉，下次请求
          //     重新解析又可能先拿到同一个死 IP，并在 60s 里反复重放整条 SSRF 校验 —— 死循环式浪费。
          if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
            const hostname = opts.url ? new URL(opts.url).hostname : null;
            if (hostname) {
              dnsCache.delete(hostname);
              clearHostPin(hostname);
            }
          }
          logger.warn(`HTTP 不可重试错误（快速失败）：${err.code} ${err.message}`);
          throw new AppError(ErrorCode.HTTP_ERROR, err.message || 'HTTP 请求失败');
        }
        if (isTimeout) {
          // P2-5：日志 URL 打码（剥离 query 中的注入 payload/敏感参数）
          // 文案区分「还会重试」与「最后一次尝试」（retry=0 时旧文案"第 1 次重试"误导）：
          logger.warn(
            attempt < retry
              ? `HTTP 超时（第 ${attempt + 1}/${retry + 1} 次尝试，将重试）：${logSafeUrl(opts.url || '')}`
              : `HTTP 超时（已达重试上限，放弃）：${logSafeUrl(opts.url || '')}`
          );
        } else {
          logger.warn(
            attempt < retry
              ? `HTTP 错误（第 ${attempt + 1}/${retry + 1} 次尝试，将重试）：${logSafeUrl(opts.url || '')} ${err.message}`
              : `HTTP 错误（已达重试上限，放弃）：${logSafeUrl(opts.url || '')} ${err.message}`
          );
        }
        if (attempt < retry) {
          const backoffMs = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_MAX_MS);
          // [P2-FIX] 退避期间响应 abort signal（_sleep 可中断）：点了停止不必等完 backoff
          await this._sleep(backoffMs, opts.signal);
          if (opts.signal?.aborted) {
            const abortErr = /** @type {NodeJS.ErrnoException} */ (new Error('请求已取消（扫描停止）'));
            abortErr.name = 'AbortError';
            abortErr.code = 'ERR_CANCELED';
            throw abortErr;
          }
          continue;
        }
        if (isTimeout) throw new AppError(ErrorCode.HTTP_TIMEOUT, '请求超时');
      }
    }
    throw new AppError(ErrorCode.HTTP_ERROR, lastErr?.message || 'HTTP 请求失败');
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

export const httpClient = new HttpClient();
export { dnsCache, EXTRACT_MAX_BODY_BYTES, MAX_BODY_BYTES };
export default httpClient;

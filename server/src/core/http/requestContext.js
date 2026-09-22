// ============================================================================
// requestContext.js —— httpClient 的「纯决策 / 纯工具」helper 集合
// ----------------------------------------------------------------------------
// [大文件三期拆分 2026-09-22] 从 core/httpClient.js 抽出。这些函数的共同点是
// **不持有 HttpClient 实例状态、不直接发请求**，因此可以脱离 I/O 单测，
// 也可被重定向 / 代理 / 认证等子路径共用。
//
// ⚠️ 拆分策略：**符号一律 re-export 回 httpClient.js**。
//    既有调用方（`server/bin/cli.js`、`src/config/defaults.js`）与测试
//    （`httpClient.p2.test.js` / `httpClient.egressHardening.test.js` /
//    `httpClient.protocol.test.js`）都从 `httpClient.js` 取这些符号，
//    保持路径不变 = 拆分对调用方零影响（与二期 http/ 拆分同一约定）。
//
// 内容分组：
//   ① 头合并与黑名单（mergeAuthHeaders / FORBIDDEN_HEADERS）
//   ② 日志脱敏（logSafeUrl）
//   ③ 认证类确定性判定（effectiveInsecureTls）
//   ④ 出口语义决策（resolveEgressPolicy）
// ============================================================================

import { defaults } from '../../config/defaults.js';
import { logger } from '../logger.js';
import { resolveProxy } from './proxy.js';

// ── ① 认证头合并（P2-8：头名黑名单）────────────────────────────────────────────
// 禁止调用者通过 auth.headers / headerParams 覆写以下头，防止请求走私/虚拟主机绕过
export const FORBIDDEN_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'proxy-connection',
  'keep-alive',
  'te',
  'trailer',
  'expect',
]);

/**
 * 合并基础请求头与认证信息（Basic Auth / Cookie / 自定义头），
 * 对 FORBIDDEN_HEADERS 黑名单中的头名做拒绝覆写（防请求走私）。
 * @param {Record<string,string>} headers 基础请求头
 * @param {object} [auth] 认证配置 { basic:{username,password}, cookie, headers }
 * @returns {Record<string,string>} 合并后的请求头
 */
export function mergeAuthHeaders(headers, auth) {
  const h = { ...(headers || {}) };
  // [P0-FIX 2026-09-09] 基础头同样过黑名单。此前只有 `auth.headers` 会被拦，`headers`（调用方
  // 传入 / 原始请求解析出来的那一份）原样透传 —— 于是 REST 入口的 headerParams 过滤成了唯一防线：
  // 任何绕过 REST 的路径（库用法、新加的客户端路由）都能把 Transfer-Encoding / Content-Length
  // 塞进出口，对目标前置代理就是请求走私。Host 留作例外：按 IP 直连 + 改 Host 打 vhost 是合法需求，
  // 而 REST 入口仍按原策略连 Host 一起拒（那一层面向不可信调用者）。
  for (const key of Object.keys(h)) {
    const lk = String(key).toLowerCase();
    if (lk === 'host') continue;
    if (FORBIDDEN_HEADERS.has(lk)) {
      logger.warn(`出口头清洗：忽略调用方设置的传输层头 ${key}（由传输层自行决定，防请求走私）`);
      delete h[key];
    }
  }
  if (!auth) return h;
  // [P1-2026-09-14] NTLM 模式不发 Basic 头：NTLM 走自己的三步握手（Type1→Type2→Type3），
  // 预置 Basic 会 ① 让首请求平白吃一次 401 ② 挡住 Type3 的预附加（已有 Authorization 则不附加）
  // → 同主机后续请求每次都重走握手（实测复用失效：第二次仍 3 次请求）。
  const authIsNtlm = auth.type && String(auth.type).toLowerCase() === 'ntlm';
  if (auth.basic && auth.basic.username != null && !authIsNtlm) {
    const user = auth.basic.username;
    const pass = auth.basic.password != null ? auth.basic.password : '';
    h['Authorization'] = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  }
  if (auth.cookie) {
    const existing = h['Cookie'] ? String(h['Cookie']).replace(/;?\s*$/, '') : '';
    h['Cookie'] = existing ? `${existing}; ${auth.cookie}` : auth.cookie;
  }
  if (auth.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (FORBIDDEN_HEADERS.has(String(k).toLowerCase())) {
        logger.warn(`合并认证头时忽略禁止覆写的头：${k}`);
        continue;
      }
      h[k] = v;
    }
  }
  return h;
}

// ── ② 日志安全 URL（P2-5）─────────────────────────────────────────────────────
/**
 * 日志安全 URL（P2-5）：仅保留 scheme+host+path，query 值整体打码（防 payload/敏感参数进日志）。
 * @param {string} urlString 原始 URL
 * @returns {string} 脱敏后的 URL 字符串
 */
export function logSafeUrl(urlString) {
  try {
    const u = new URL(urlString);
    u.search = '?...'; // 打码全部 query
    u.hash = '';
    return u.toString();
  } catch {
    return String(urlString).slice(0, 200);
  }
}

// ── ③ insecureTls 生效值 ──────────────────────────────────────────────────────
/**
 * 解析 insecureTls 生效值：请求级覆盖（opts.insecureTls，供未来按扫描下发）→ 全局默认。
 * 接受 true/1/'true'/'1'（与仓库其它 env 风格一致），其余一律 false。
 * @param {object} [opts] 请求选项
 * @returns {boolean}
 */
export function effectiveInsecureTls(opts) {
  const v = opts && opts.insecureTls !== undefined ? opts.insecureTls : defaults.insecureTls;
  return v === true || v === 1 || v === '1' || v === 'true';
}

// ── ④ 出口语义决策（P1-FIX 2026-09-08 ①②）─────────────────────────────────────
/**
 * 由请求选项决定本次请求的「出口语义」（是否经代理 / 代理来源 / 是否关闭证书校验 /
 * SSRF 判定是否下放给代理），并据此产生 socks5:// 的本地解析提示。
 *
 * 抽成纯函数的意义：出口语义是**顺序敏感**的决策（先定出口 → 再做 SSRF 校验：
 * 是否走代理决定本地能否解析目标），把它与请求流程解耦后可直接单测，
 * 也避免在 request() 里继续堆积条件分支。
 *
 * ⚠️ 副作用：仅在「经 socks5:// 代理且目标是域名」时 `logOnce` 一条**一次性**提示
 *（不擅改语义 —— 静默升级成远端解析等于替用户改了代理行为）。
 *
 * @param {object} opts 请求选项
 * @returns {{
 *   insecureTls: boolean,
 *   proxyUrl: string|null,
 *   proxySource: 'config'|'env'|null,
 *   egress: { viaProxy: boolean, proxySource: 'config'|'env'|null, insecureTls: boolean, ssrfViaProxy: string },
 * }}
 */
export function resolveEgressPolicy(opts) {
  const insecureTls = effectiveInsecureTls(opts);
  // [P1-FIX ②] 代理来源：显式配置 → *PROXY 环境变量（curl/sqlmap 语义）；https:// 代理在此被显式拒绝。
  // 注意 opts.proxy 为 false 表示「未配置」（调用方统一写 `config.proxy ?? false`），不是「禁用」。
  const proxySel = resolveProxy(opts.proxy ?? defaults.proxy ?? false, {
    targetUrl: opts.url,
    trustProxyEnv: opts.trustProxyEnv ?? defaults.trustProxyEnv !== false,
    proxyBypassLocal: opts.proxyBypassLocal ?? defaults.proxyBypassLocal !== false,
  });
  const egress = {
    viaProxy: !!proxySel.proxyUrl,
    proxySource: proxySel.source,
    insecureTls,
    ssrfViaProxy: String(opts.ssrfViaProxy ?? defaults.ssrfViaProxy ?? 'auto').toLowerCase(),
  };
  return { insecureTls, proxyUrl: proxySel.proxyUrl, proxySource: proxySel.source, egress };
}

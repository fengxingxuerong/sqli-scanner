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
 * [D91 拆分] 把 auth.headers 的逐键合并提为子函数（原为 mergeAuthHeaders 内联循环，
 * D91 加 Cookie 同名跳过条件后函数体/圈复杂度双超基线，按仓库纪律拆函数而非抬基线）。
 *
 * 含 [D91 2026-10-17 真回归修复·第二道防线]：Cookie 同名（大小写不敏感）且请求头已有
 * Cookie 时跳过。理由：`--header "cookie: X"` 会被 TargetParser 同时存进 headerParams
 * （→ cookie 注入点的注入值）与 config.auth.headers（→ 本分支每请求重附原值）；若无条件
 * 覆盖，注入值又被原值顶掉，与 A 处（injection.js）的构造层双键歧义叠加成「原值必胜」。
 * 语义：显式构造的 Cookie（注入值/调用方指定）优先于认证配置里的同名副本。
 * @param {Record<string,string>} h 已合并的基础头（就地修改）
 * @param {object} authHeaders 认证配置里的自定义头
 */
function mergeAuthCustomHeaders(h, authHeaders) {
  for (const [k, v] of Object.entries(authHeaders)) {
    const lk = String(k).toLowerCase();
    if (FORBIDDEN_HEADERS.has(lk)) {
      logger.warn(`合并认证头时忽略禁止覆写的头：${k}`);
      continue;
    }
    if (lk === 'cookie' && (h['Cookie'] || h['cookie'])) {
      continue;
    }
    h[k] = v;
  }
}

/**
 * [D101 2026-10-18] 追加 auth.cookie 到请求头 Cookie —— 大小写不敏感找现有键并**归一为单键**。
 * 此前只查大写 `h['Cookie']`：请求头里是小写 `cookie` 时判空 ⇒ auth.cookie 另起大写键 ⇒
 * axios 归并同名头后写赢，吞掉原串（注入值/会话 cookie 双丢）。归一后追加语义在任何大小写
 * 形态下都真实生效。抽为独立函数的原因：mergeAuthHeaders 有复杂度基线（只许持平）。
 * @param {Record<string,string>} h 已合并的基础头（就地修改）
 * @param {string} authCookie auth.cookie 串
 */
function appendAuthCookie(h, authCookie) {
  const existingKeys = Object.keys(h).filter((k) => k.toLowerCase() === 'cookie');
  const existing = existingKeys.length ? String(h[existingKeys[0]]).replace(/;?\s*$/, '') : '';
  for (const k of existingKeys) delete h[k];
  h['Cookie'] = existing ? `${existing}; ${authCookie}` : authCookie;
}

/**
 * [D101 2026-10-18] Basic 预置跳过判定：NTLM 模式（[P1-2026-09-14] 既有语义：NTLM 走三步
 * 握手，预置 Basic 会平白吃一次 401 且挡住 Type3 预附加 ⇒ 同主机后续请求重走握手），或请求头
 * 已带 Authorization（REST headerParams 的 authorization 注入点/调用方显式自带）——
 * mergeAuthHeaders 末尾写入会覆盖它，「显式构造优先于认证配置同名副本」与 D91-B 的 Cookie
 * 语义对齐。抽为独立函数的原因同上（复杂度基线）。
 * @param {object} auth 认证配置
 * @param {Record<string,string>} h 已合并的基础头
 * @returns {boolean}
 */
function shouldSkipBasicAuth(auth, h) {
  if (auth.type && String(auth.type).toLowerCase() === 'ntlm') return true;
  return Object.keys(h).some((k) => k.toLowerCase() === 'authorization');
}

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
  if (auth.basic && auth.basic.username != null && !shouldSkipBasicAuth(auth, h)) {
    const user = auth.basic.username;
    const pass = auth.basic.password != null ? auth.basic.password : '';
    h['Authorization'] = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  }
  if (auth.cookie) appendAuthCookie(h, auth.cookie);
  if (auth.headers && typeof auth.headers === 'object') {
    mergeAuthCustomHeaders(h, auth.headers);
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

// mTLS 客户端证书路径（PEM 文件，证书+私钥同文件，对标 sqlmap --cert）：
// opts 优先，defaults 兜底；空串/非字符串视为未配置。
export function effectiveClientCert(opts) {
  const v = opts && opts.clientCert !== undefined ? opts.clientCert : defaults.clientCert;
  return typeof v === 'string' && v.trim() ? v.trim() : null;
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

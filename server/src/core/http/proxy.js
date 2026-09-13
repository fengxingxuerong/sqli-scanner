// ============================================================================
// http/proxy.js —— 代理解析与可用性/豁免判定
//
// 从 httpClient.js 拆出（2026-09-14 大文件二期拆分）。**纯搬移，行为不变**。
// 拆分原因：httpClient.js 已 1712 行（arch-guard 判定为技术债「只减不增」），
// 而这一组是**自包含的安全判定逻辑**，与 HTTP 传输层无耦合 → 抽成独立模块既过门禁，
// 也让 SSRF/代理规则可被单独测试。
// ============================================================================
import { ErrorCode, AppError } from '../errors.js';
import { logOnce, infoOnce } from './logOnce.js';
import { defaults } from '../../config/defaults.js';

const PROXY_SCHEMES = new Set(['socks5', 'socks5h', 'socks4', 'socks4a', 'socks', 'http', 'https']);
const SOCKS_PROXY_SCHEMES = new Set(['socks5', 'socks5h', 'socks4', 'socks4a', 'socks']);

/**
 * 解析代理 URL 并校验 scheme；非法 URL / 白名单外协议直接抛 AppError（INVALID_PARAM）。
 * @param {string} proxyUrl 代理 URL
 * @returns {{u: URL, scheme: string}} URL 对象与小写 scheme（不含冒号）
 */
function parseProxyUrl(proxyUrl) {
  let u;
  try {
    u = new URL(String(proxyUrl));
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, `代理 URL 格式非法：${String(proxyUrl).slice(0, 120)}`);
  }
  const scheme = String(u.protocol || '').replace(/:$/, '').toLowerCase();
  if (!PROXY_SCHEMES.has(scheme)) {
    throw new AppError(
      ErrorCode.INVALID_PARAM,
      `不支持的代理协议: ${scheme || '(空)'}（支持 socks5/socks4/http/https）`
    );
  }
  return { u, scheme };
}

/**
 * [P1-FIX ②] 请求前代理可用性检查：scheme 白名单 + https:// 代理显式拒绝。
 * 为何不「顺手支持」https 代理：axios 仅在目标为 https 时建 CONNECT 隧道，http:// 目标会把
 * 绝对 URI 明文发到 TLS 端口（要么握手失败、要么明文泄漏）。同一份配置两种语义比「明确不可用」
 * 更危险，故要求填 http:// 本地转发（Burp / proxychains / privoxy 默认都是 http 代理）。
 * @param {string|null} [proxyUrl] 代理 URL
 * @returns {string|null} 校验通过的 scheme（无代理时 null）
 */
export function assertProxyUsable(proxyUrl) {
  if (!proxyUrl) return null;
  const { scheme } = parseProxyUrl(proxyUrl);
  if (scheme === 'https') {
    throw new AppError(
      ErrorCode.INVALID_PARAM,
      'https:// 代理不支持（仅 https 目标会被隧道，http 目标会被明文发到 TLS 端口）；' +
        '请改用 http:// 本地转发（Burp 即 http 代理，如 http://127.0.0.1:8080）'
    );
  }
  return scheme;
}

/**
 * [P0-FIX 2026-09-09] 本地/私网主机判定（代理豁免用，语义对齐 curl 默认行为）。
 * 命中即不应把请求送进「环境变量代理」——代理通常不对 localhost 提供服务，
 * 失败后会被上层当成「目标无漏洞」，造成假阴性。
 * @param {string} host 主机名或 IP 字面量
 * @returns {boolean}
 */
export function isLocalOrPrivateHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0') return true;
  if (h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  const m = h.match(/^172\.(\d{1,3})\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (/^169\.254\./.test(h)) return true;
  return false;
}

/**
 * NO_PROXY 条目匹配：支持 '*'、逗号分隔、可选前导点 / '*.‘、以及域名后缀
 * （foo.example.com 命中 example.com），条目可带端口（端口不参与匹配）。
 * @param {string} noProxy NO_PROXY 原始值
 * @param {string} host 目标主机名
 * @returns {boolean} 命中豁免（不走代理）
 */
export function isNoProxyHost(noProxy, host) {
  if (!noProxy || !host) return false;
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  for (const raw of String(noProxy).split(',')) {
    const e = raw.trim().toLowerCase().replace(/^\*\./, '').replace(/^\./, '').replace(/\/.*$/, '');
    if (!e || e === '*') return true;
    const entry = e.split(':')[0];
    if (!entry) continue;
    if (h === entry || h.endsWith(`.${entry}`)) return true;
  }
  return false;
}

/**
 * [P1-FIX ②] 解析本次请求实际使用的代理（对标 curl / sqlmap 的环境变量语义）。
 * 优先级：显式配置（opts.proxy / defaults.proxy）→ HTTPS_PROXY → https_proxy → HTTP_PROXY →
 * http_proxy → ALL_PROXY；NO_PROXY 命中目标 host 时不走代理。
 * 注意：本仓库调用方统一以 `proxy: config.proxy ?? false` 透传，故 false / 空串一律视为「未配置」
 * （而非「显式禁用」）；要在有全局代理的机器上强制直连，用 trustProxyEnv=false（唯一逃生口）。
 * @param {string|false|null} [configuredProxy] 显式配置的代理 URL
 * @param {{targetUrl?:string, trustProxyEnv?:boolean, proxyBypassLocal?:boolean}} [opts]
 *        目标 URL（NO_PROXY 用）、环境变量开关与本地/私网豁免开关
 * @returns {{proxyUrl: string|null, source: 'config'|'env'|null}}
 */
export function resolveProxy(configuredProxy, { targetUrl = '', trustProxyEnv, proxyBypassLocal } = {}) {
  const trustEnv = trustProxyEnv ?? defaults.trustProxyEnv !== false;
  const bypassLocal = proxyBypassLocal ?? defaults.proxyBypassLocal !== false;
  const configured = typeof configuredProxy === 'string' ? configuredProxy.trim() : '';
  if (configured) {
    assertProxyUsable(configured);
    return { proxyUrl: configured, source: 'config' };
  }
  if (!trustEnv) return { proxyUrl: null, source: null };
  let host = '';
  try {
    host = new URL(targetUrl).hostname;
  } catch { /* 无 URL（direct/sql 模式）→ 不做 NO_PROXY 匹配 */ }
  if (isNoProxyHost(process.env.NO_PROXY || process.env.no_proxy || '', host)) {
    return { proxyUrl: null, source: null };
  }
  // [P0-FIX 2026-09-09] 本地/私网目标默认不吃环境变量代理（NO_PROXY 为空时的兜底）。
  // 只作用于 env 来源：显式 config.proxy 是用户明确意图（就是要连本地 Burp），不受影响。
  if (host && bypassLocal && isLocalOrPrivateHost(host)) {
    infoOnce(
      `[opsec] 目标 ${host} 为本地/私网地址：本次不走环境变量代理（proxyBypassLocal=true）；` +
        '如需强制经代理请在 config.proxy 显式指定，或用 proxyBypassLocal=false 恢复旧行为'
    );
    return { proxyUrl: null, source: null };
  }
  for (const key of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY']) {
    const v = (process.env[key] || '').trim();
    if (!v) continue;
    // 环境变量常见「无 scheme」写法（127.0.0.1:8080）→ 按 http 处理（与 curl 同义）
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v) ? v : `http://${v}`;
    try {
      assertProxyUsable(candidate);
    } catch (e) {
      // 环境变量代理不可用（如 HTTPS_PROXY=socks6://…）→ 明确报错而非静默直连：
      // 静默回退直连会让用户以为流量走了代理（opsec 事故），这里不留余地。
      throw e instanceof AppError ? e : new AppError(ErrorCode.INVALID_PARAM, `环境变量代理 ${key} 非法：${v}`);
    }
    infoOnce(`[opsec] 未配置 proxy，命中环境变量代理 ${key}=${v}：本次起所有出站请求经该代理发出（NO_PROXY 可豁免，trustProxyEnv=false 可整体忽略）`);
    return { proxyUrl: candidate, source: 'env' };
  }
  return { proxyUrl: null, source: null };
}

/**
 * [P1-FIX ②] 出口目标校验（含代理语义）：
 * · 未走代理，或 ssrfViaProxy='off' → 完全等价 assertSafeHttpTarget（零行为变化）。
 * · 已走代理且 ssrfViaProxy='auto' → 跳过本地 DNS 解析与严格层私网判定（解析发生在代理侧，
 *   本地判定既无意义又会阻断「域名只能经 Burp 解析」的合法授权目标），但 IP 字面量仍按
 *   硬底线（0.0.0.0/8、169.254.0.0/16、组播/保留段）无条件拒绝。
 * · ssrfViaProxy='strict-dns' → 本地能解析就先按严格层判（解析不出才下放给代理）。
 *   实战场景：内网 DNS 把某个「看起来无害」的域名指到 169.254.169.254（元数据服务）时，
 *   auto 语义下代理会照打（代理自己会解析），边界完全转移到代理配置上；strict-dns 把这道门
 *   要回来，代价是「只能经代理解析的域名」会退化成放行（仍会记一条日志）。
 * @param {string} urlString 目标 URL
 * @param {{viaProxy?:boolean, ssrfViaProxy?:string}|null} [egress] 本次请求的出口语义（null = 未指定）
 */

// 注：assertProxyUsable / isLocalOrPrivateHost / isNoProxyHost / resolveProxy 在搬移体内已是
// `export function`，此处只补导出内部使用的 parseProxyUrl。
export { parseProxyUrl, SOCKS_PROXY_SCHEMES, PROXY_SCHEMES };

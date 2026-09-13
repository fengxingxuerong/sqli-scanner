// ============================================================================
// http/egressGuard.js —— SSRF 防护 / 出口目标校验
//
// 从 httpClient.js 拆出（2026-09-14 大文件二期拆分）。**纯搬移，行为不变**。
// 拆分原因：httpClient.js 已 1712 行（arch-guard 判定为技术债「只减不增」），
// 而这一组是**自包含的安全判定逻辑**，与 HTTP 传输层无耦合 → 抽成独立模块既过门禁，
// 也让 SSRF/代理规则可被单独测试。
// ============================================================================
import net from 'node:net';
import dns from 'node:dns';
import { URL } from 'node:url';
import { ErrorCode, AppError } from '../errors.js';
import { logOnce, PROXY_DELEGATION_NOTE } from './logOnce.js';
import { defaults } from '../../config/defaults.js';
import { logger } from '../logger.js';

// ── SSRF 防护（P0-1）────────────────────────────────────────────────────────
// 分层策略（按 env 决定拒绝集合）：
//   · 基础层（无条件拒绝）：0.0.0.0/8、链路本地 169.254.0.0/16（含云元数据 169.254.169.254）、
//     组播/保留/文档段 —— 对扫描器自身没有任何合法扫描价值，是 SSRF 最高价值目标。
//   · 严格层（SSRF_STRICT=1 时追加）：回环 127.0.0.0/8、::1、私网 10/8、172.16/12、192.168/16、
//     CGNAT 100.64/10、ULA fc00::/7 —— 面向「引擎暴露在非回环接口」的部署（容器/局域网/公网）。
//   · 显式放行（优先级最高）：SSRF_ALLOW_PRIVATE=1 完全放行；SSRF_ALLOW_CIDRS=1.2.3.0/24,...
//     逐段放行（供内部授权目标/测试使用）。
const POLICY = (() => {
  const allowAll = process.env.SSRF_ALLOW_PRIVATE === '1' || process.env.SSRF_ALLOW_PRIVATE === 'true';
  const strict =
    process.env.SSRF_STRICT === '1' ||
    process.env.SSRF_STRICT === 'true' ||
    (process.env.HOST && process.env.HOST !== '127.0.0.1' && process.env.HOST !== 'localhost');
  const allowCidrs = (process.env.SSRF_ALLOW_CIDRS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return { allowAll, strict, allowCidrs };
})();

function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]) >>> 0);
}

// IPv6 判定：先处理 IPv4 映射（::ffff:x.x.x.x），再按前缀规则精确判断
function ipv6InPrefix(ip, prefix, bits) {
  const lower = ip.toLowerCase();
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIpv4(mapped[1]);
  if (bits === 128) return lower === prefix; // 精确匹配（如 ::1）
  if (prefix === 'fe80::' && bits === 10) {
    const first = lower.split(':')[0] || '';
    return /^fe[89ab]$/.test(first); // fe80::/10
  }
  if (prefix === 'fc00::' && bits === 7) {
    const first = lower.split(':')[0] || '';
    return /^f[cd]$/.test(first); // fc00::/7（ULA）
  }
  return false;
}

// [P1-FIX 2026-09-08 ②] hardOnly=true：只看「基础层（硬底线）」，忽略 SSRF_ALLOW_PRIVATE/ALLOW_CIDRS
// 显式放行与严格层。用于「已配代理 + ssrfViaProxy!=='off'」：解析与路由都发生在代理侧，本地无法
// 判定目标是否内网，但 0.0.0.0/8、169.254.0.0/16（云元数据）、组播/保留段这些对扫描器零合法价值的
// IP 字面量仍无条件拒绝 —— 否则代理就沦为直达元数据的白名单。
function isBlockedIpv4(ip, hardOnly = false) {
  const n = ipToLong(ip);
  if (n === null) return false;
  const inCidr = (a, b, c, d, bits) => {
    const base = ((a * 16777216 + b * 65536 + c * 256 + d) >>> 0);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) === (base & mask);
  };
  // 显式放行优先（硬底线模式不受放行清单影响）
  if (hardOnly) { /* 硬底线：忽略 allowAll / allowCidrs */ }
  else if (POLICY.allowAll) return false;
  else if (POLICY.allowCidrs.some((cidr) => {
    const [h, bitsStr] = cidr.split('/');
    const parts = (h || '').split('.').map(Number);
    if (parts.length !== 4) return false;
    const bits = parseInt(bitsStr, 10);
    if (!Number.isFinite(bits) || bits < 0 || bits > 32) return false;
    return inCidr(parts[0], parts[1], parts[2], parts[3], bits);
  })) return false;
  // 基础层：永远拒绝
  if (inCidr(0, 0, 0, 0, 8)) return true; // 0.0.0.0/8
  if (inCidr(169, 254, 0, 0, 16)) return true; // 链路本地 + 云元数据 169.254.169.254
  if (inCidr(224, 0, 0, 0, 4)) return true; // 组播
  if (inCidr(240, 0, 0, 0, 4)) return true; // 保留
  if (inCidr(192, 0, 2, 0, 24) || inCidr(198, 51, 100, 0, 24) || inCidr(203, 0, 113, 0, 24)) return true; // 文档段
  if (inCidr(192, 0, 0, 0, 24) || inCidr(198, 18, 0, 0, 15)) return true; // IETF 保留/基准测试段
  if (inCidr(100, 64, 0, 0, 10)) return true; // CGNAT
  if (hardOnly) return false; // 硬底线到此为止：严格层（回环/私网）在代理模式下由代理侧判定
  // 严格层
  if (POLICY.strict) {
    if (inCidr(127, 0, 0, 0, 8)) return true; // 回环
    if (inCidr(10, 0, 0, 0, 8)) return true;
    if (inCidr(172, 16, 0, 0, 12)) return true;
    if (inCidr(192, 168, 0, 0, 16)) return true;
  }
  return false;
}

function isBlockedIp(ip, hardOnly = false) {
  const v = net.isIP(ip);
  if (v === 4) return isBlockedIpv4(ip, hardOnly);
  if (v === 6) {
    // 无条件拒绝：未指定 ::、回环 ::1 仅在严格层拒绝、链路本地 fe80::/10 与 ULA fc00::/7 永远拒绝
    if (ipv6InPrefix(ip, 'fe80::', 10)) return true; // 链路本地（含云元数据 IPv6 变体）
    if (ip === '::') return true; // 未指定
    if (hardOnly) return false; // [P1-FIX ②] 硬底线模式：ULA fc00::/7 与 ::1 等价 v4 私网，下放代理侧判定
    if (ipv6InPrefix(ip, 'fc00::', 7)) return true; // ULA（等价私网）
    if (POLICY.strict && ipv6InPrefix(ip, '::1', 128)) return true; // 回环（严格层）
    return false;
  }
  return false;
}

// 主机名 → IP 解析缓存（60s TTL，防每次请求重复 DNS）
const dnsCache = new Map();
const DNS_CACHE_TTL = 60000;
// 定期清理过期 DNS 缓存条目（每 5 分钟）
// P1: 同步清理 _dnsPinIndex 过期条目（与 dnsCache 同步生命周期，防 Map 无界增长）
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of dnsCache) {
    if (now - val.ts >= DNS_CACHE_TTL) dnsCache.delete(key);
  }
  for (const [key, val] of _dnsPinIndex) {
    if (now - val.ts >= DNS_CACHE_TTL) _dnsPinIndex.delete(key);
  }
  for (const [key, ts] of _dnsPinBad) {
    if (now - ts >= DNS_CACHE_TTL) _dnsPinBad.delete(key);
  }
}, 300000).unref();
async function resolveHost(hostname) {
  const now = Date.now();
  const hit = dnsCache.get(hostname);
  if (hit && now - hit.ts < 60000) return hit.ips;
  // P0: dns.promises.lookup(hostname, { all: true }) 返回 [{ address, family }, ...] 数组，
  // 旧实现 const { address } = 数组 对数组对象解构取得 address 属性 → 恒为 undefined （数组
  // 对象无 address 属性），导致 ips 恒为 [] → SSRF 域名校验全部跳过，SSRF_STRICT 形同虚设。
  const records = await dns.promises.lookup(hostname, { all: true, verbatim: true }).catch(() => null) || [];
  const ips = Array.isArray(records) ? records.map((r) => r.address) : [];
  // [P0-FIX] 解析失败（records 空/解析异常）不缓存空结果：
  // 若把 [] 缓存 60s，则 assertSafeHttpTarget 对同 host 的后续校验直接命中空缓存而放行
  // （fail-open），而请求层（axios/undici）自行解析可能解析出内网 IP → 校验形同虚设。
  // 仅在确实解析到 IP 时缓存；失败路径由调用方 fail-closed（见 assertSafeHttpTarget）。
  if (ips.length > 0) dnsCache.set(hostname, { ips, ts: now });
  return ips;
}

// [P0-3] DNS 钉死辅助函数：从缓存取已校验 IP，构造 lookup 回调（防 DNS rebinding）
// 模块级函数，供 request 和 _followRedirects 共用
// [P0-FIX] IP 轮换：当缓存含多 A 记录时，记录上次尝试的 IP 索引；连接失败后轮换下一 IP。
// 避免 CDN/round-robin 目标中单 IP 宕机导致整段扫描中断 60s（ECONNREFUSED 为不可重试错误）。
// [P0-FIX 2026-09-09] 轮换语义修正：原注释写的是「连接失败后轮换下一 IP」，代码却是
// **每次请求都前移索引**（成功也前移）。后果不是「少切一次」而是反过来：
//   • 多 A 记录目标（K8s Ingress / F5 / 无 sticky 的 LB）下，同一注入点的「基线请求」与「注入请求」
//     会落到不同后端。时间盲注据此判延迟、布尔盲注据此比相似度 —— 两个样本来自两台机器，
//     σ 直接被后端负载差异污染，实战表现是「time 技术在负载均衡目标上整段不可用」；
//   • keep-alive 也永远复用不上（每次换 IP = 每次新建连接 + TLS 握手），慢目标上白白多几十毫秒，
//     而这几十毫秒正是时间盲注的噪声底。
// 新语义：默认**钉死在同一个 IP**，只有当该 IP 真的发生连接层失败（拒连/不可达）才拉黑并前移，
// 拉黑条目随 DNS 缓存同 TTL 过期（CDN 节点恢复后自动回到它）。
const _dnsPinIndex = new Map(); // hostname -> { idx, ts }
const _dnsPinBad = new Map(); // `hostname|ip` -> ts（近期连接层失败的出口 IP）

// 只有「连不上」类错误才说明这个节点可能死了；超时/响应类错误不能拿来判节点死刑
// （目标被我们自己的重载荷拖慢是常态，据此换 IP 会把一整轮盲注打散到不同后端，正好造成本修复要消除的问题）。
const IP_FAIL_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE', 'ECONNRESET']);

function buildPinnedLookup(url) {
  try {
    const hostname = new URL(url).hostname;
    const cached = dnsCache.get(hostname);
    if (cached && cached.ips.length > 0) {
      const now = Date.now();
      const ips = cached.ips;
      const p = _dnsPinIndex.get(hostname) || { idx: 0, ts: now };
      let chosen = null;
      let chosenOffset = 0;
      for (let k = 0; k < ips.length; k++) {
        const cand = ips[(p.idx + k) % ips.length];
        const badTs = _dnsPinBad.get(`${hostname}|${cand}`);
        if (badTs == null || now - badTs >= DNS_CACHE_TTL) {
          if (badTs != null) _dnsPinBad.delete(`${hostname}|${cand}`);
          chosen = cand;
          chosenOffset = k;
          break;
        }
      }
      if (chosen == null) {
        // 全集群都在黑名单里（整站宕 / 我们误判了一轮）：清空黑名单并从第一个 IP 重来，
        // 绝不能让工具自己的黑名单变成「这个目标扫不了」。
        for (const key of [..._dnsPinBad.keys()]) if (key.startsWith(`${hostname}|`)) _dnsPinBad.delete(key);
        chosen = ips[0];
        chosenOffset = 0;
      }
      _dnsPinIndex.set(hostname, { idx: (p.idx + chosenOffset) % ips.length, ts: now });
      const family = net.isIP(chosen) || 4;
      const ip = chosen;
      return (h, o, cb) => cb(null, ip, family);
    }
  } catch { /* 若 URL 解析失败则不钉死 */ }
  return undefined;
}

/**
 * 记一次出口 IP 的连接层失败：拉黑当前钉死的 IP，并把索引前移，使下一次（含本次重试）打到别的节点。
 * @param {string} url 请求 URL
 * @param {string} [code] 错误码（仅用于日志）
 */
export function noteEgressIpFailure(url, code = '') {
  try {
    const hostname = new URL(url).hostname;
    const cached = dnsCache.get(hostname);
    const p = _dnsPinIndex.get(hostname);
    if (!cached || !cached.ips?.length) return;
    const idx = p ? p.idx % cached.ips.length : 0;
    const ip = cached.ips[idx];
    if (!ip) return;
    _dnsPinBad.set(`${hostname}|${ip}`, Date.now());
    if (cached.ips.length > 1) {
      _dnsPinIndex.set(hostname, { idx: (idx + 1) % cached.ips.length, ts: Date.now() });
      logger.warn(`出口 IP ${ip} 连接层失败${code ? `（${code}）` : ''}：目标 ${hostname} 后续请求改用下一个已校验 IP（共 ${cached.ips.length} 个）`);
    } else {
      logger.warn(`出口 IP ${ip} 连接层失败${code ? `（${code}）` : ''}：${hostname} 无其他候选 IP，继续按原地址重试`);
    }
  } catch { /* 记账失败不影响请求 */ }
}

/** 域名整体解析失败/记录已失效时清空该主机的钉死状态（下次重新解析、重新建立 IP 列表） */
function clearHostPin(hostname) {
  _dnsPinIndex.delete(hostname);
  for (const key of [..._dnsPinBad.keys()]) if (key.startsWith(`${hostname}|`)) _dnsPinBad.delete(key);
}

/**
 * 校验 http(s) 目标 URL 是否允许引擎出站访问（SSRF 防护）。
 * 规则：scheme 必须 http/https；主机名解析后的任一 IP 命中拒绝集合 → 抛 AppError。
 * 供 scanRoutes / exploitRoutes / sqlmapRoutes / TargetParser / SecondOrder 复用。
 * @param {string} urlString
 */
export async function assertSafeHttpTarget(urlString) {
  let u;
  try {
    u = new URL(urlString);
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, '目标 URL 格式非法');
  }
  if (!/^https?:$/i.test(u.protocol)) {
    throw new AppError(ErrorCode.INVALID_PARAM, '仅支持 http/https 目标');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) throw new AppError(ErrorCode.INVALID_PARAM, '目标缺少主机名');
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new AppError(ErrorCode.INVALID_PARAM, '目标 IP 位于禁止访问的地址段（SSRF 防护）');
    return;
  }
  const ips = await resolveHost(host).catch(() => []);
  if (ips.length === 0) {
    // [P0-FIX] fail-closed：DNS 解析失败（域名不存在 / 解析异常）时拒绝出站，而非放行。
    // 原实现 return 放行 → 攻击者可利用「先解析失败再解析到 169.254.169.254」的时序窗口
    // （失败不缓存后，请求层自行解析到内网 IP 即绕过校验）。无法证明目标安全 → 拒绝。
    throw new AppError(ErrorCode.INVALID_PARAM, `目标主机 ${host} DNS 解析失败，拒绝出站（SSRF 防护）`);
  }
  for (const ip of ips) {
    if (isBlockedIp(ip)) {
      throw new AppError(ErrorCode.INVALID_PARAM, `目标主机 ${host} 解析到禁止访问的地址 ${ip}（SSRF 防护）`);
    }
  }
}

// ── [P1-FIX 2026-09-08 ②] 代理协议白名单 / 环境变量代理 / 目标校验下放 ──────────
// 只承认下列 scheme：socks* 交给 SocksProxyAgent（socks4/4a/5/5h 由该库自行分辨），http/https
// 交给 axios 原生 proxy。旧实现对任意 scheme 一律 conf.proxy={protocol,host,port}：socks4://、
// proxy:// 之类会被当成 http 明文代理发出（Cookie/Basic 凭据与 payload 走错通道即泄漏），
// 故显式拒绝而不是「猜一个能用的」。
/**
 * @param {string} urlString
 * @param {null | {viaProxy?: boolean, ssrfViaProxy?: string}} [egress]
 */
export async function assertSafeTargetForEgress(urlString, egress = null) {
  const mode = String(egress?.ssrfViaProxy ?? 'auto').toLowerCase();
  const relaxed =
    !!egress &&
    egress.viaProxy === true &&
    mode !== 'off';
  if (!relaxed) return assertSafeHttpTarget(urlString);
  let u;
  try {
    u = new URL(urlString);
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, '目标 URL 格式非法');
  }
  if (!/^https?:$/i.test(u.protocol)) {
    throw new AppError(ErrorCode.INVALID_PARAM, '仅支持 http/https 目标');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) throw new AppError(ErrorCode.INVALID_PARAM, '目标缺少主机名');
  if (mode === 'strict-dns' && !net.isIP(host)) {
    // 本地解析得出来就自己判，不依赖代理的解析结果；解析不出来才回到「下放给代理」。
    const ips = await resolveHost(host).catch(() => []);
    for (const ip of ips || []) {
      if (isBlockedIp(ip, true)) {
        throw new AppError(
          ErrorCode.INVALID_PARAM,
          `目标 ${host} 在本机解析到禁止访问的地址段 ${ip}（ssrfViaProxy=strict-dns：已拦，未交给代理解析）`
        );
      }
    }
    if (!ips || ips.length === 0) {
      logOnce('warn', `ssrfViaProxy=strict-dns：${host} 本地无法解析，本次仍按下放代理处理（边界在代理侧）`);
    }
  }
  if (net.isIP(host)) {
    // IP 字面量不需要解析即可判定 → 硬底线段即使在代理模式下也不放行（否则代理沦为直达元数据的通道）
    if (isBlockedIp(host, true)) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        '目标 IP 位于禁止访问的地址段（SSRF 防护，代理模式亦不豁免）'
      );
    }
  }
  logOnce('warn', PROXY_DELEGATION_NOTE);
}

// 注：assertSafeHttpTarget / assertSafeTargetForEgress / noteEgressIpFailure 在搬移体内已是
// `export function`，此处只补导出「原文件内部使用、httpClient 仍需消费」的符号。
export { isBlockedIp, isBlockedIpv4, resolveHost, buildPinnedLookup, clearHostPin, dnsCache, IP_FAIL_CODES };

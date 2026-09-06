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
// 测试套件本地起 mock 目标（127.0.0.1）时请设置环境变量 SSRF_ALLOW_PRIVATE=1。
// ============================================================================

import axios from 'axios';
import http from 'node:http';
import https from 'node:https';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { URL } from 'url';
import net from 'node:net';
import dns from 'node:dns';
import { Agent as UndiciAgent, request as undiciRequest } from 'undici';
import { defaults } from '../config/defaults.js';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';
import { CookieJar } from './cookieJar.js';
import { parseDigestChallenge, extractDigestChallenge, buildDigestHeader, makeCnonce } from './digestAuth.js';

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

function isBlockedIpv4(ip) {
  const n = ipToLong(ip);
  if (n === null) return false;
  const inCidr = (a, b, c, d, bits) => {
    const base = ((a * 16777216 + b * 65536 + c * 256 + d) >>> 0);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) === (base & mask);
  };
  // 显式放行优先
  if (POLICY.allowAll) return false;
  if (POLICY.allowCidrs.some((cidr) => {
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
  // 严格层
  if (POLICY.strict) {
    if (inCidr(127, 0, 0, 0, 8)) return true; // 回环
    if (inCidr(10, 0, 0, 0, 8)) return true;
    if (inCidr(172, 16, 0, 0, 12)) return true;
    if (inCidr(192, 168, 0, 0, 16)) return true;
  }
  return false;
}

function isBlockedIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return isBlockedIpv4(ip);
  if (v === 6) {
    // 无条件拒绝：未指定 ::、回环 ::1 仅在严格层拒绝、链路本地 fe80::/10 与 ULA fc00::/7 永远拒绝
    if (ipv6InPrefix(ip, 'fe80::', 10)) return true; // 链路本地（含云元数据 IPv6 变体）
    if (ipv6InPrefix(ip, 'fc00::', 7)) return true; // ULA（等价私网）
    if (ip === '::') return true; // 未指定
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
const _dnsPinIndex = new Map(); // hostname -> { idx, ts }
function buildPinnedLookup(url) {
  try {
    const hostname = new URL(url).hostname;
    const cached = dnsCache.get(hostname);
    if (cached && cached.ips.length > 0) {
      // 轮换索引：上次尝试的索引 + 1，循环取模
      let p = _dnsPinIndex.get(hostname) || { idx: 0, ts: Date.now() };
      const idx = p.idx % cached.ips.length;
      const ip = cached.ips[idx];
      const family = net.isIP(ip) || 4;
      // 记录本次使用索引，下次尝试下一 IP
      _dnsPinIndex.set(hostname, { idx: (idx + 1) % cached.ips.length, ts: Date.now() });
      return (h, o, cb) => cb(null, ip, family);
    }
  } catch { /* 若 URL 解析失败则不钉死 */ }
  return undefined;
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

// 响应/请求体积上限（P1-3）：默认 5MB，SSRF_MAX_BODY_MB 可覆盖；
// 提取路径（dumpData）可传 opts.maxContentLength 请求更大的上限（如 50MB），避免大表拖库被截断。
const MAX_BODY_BYTES = (() => {
  const mb = Number(process.env.SSRF_MAX_BODY_MB) || 5;
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

// ── 令牌桶（MERGED: perf 版——并发突发修复 + 构造参数守卫）─────────────────
// 旧实现每个并发 acquire() 各自用「入口时刻 now」计算 waitMs 并睡到同一时刻，醒来后各自按
// 「入口起经过时长」补令牌再扣 1：N 个并发等待者会在同一时刻全部放行，实际突发速率 ≈ 并发数 × 设定速率。
// 修复：acquire 经 promise 链严格串行化——每个等待者只有在前一个令牌占用者结算完成后才开始计算，
// 醒来时刻的令牌数反映「上一请求之后的真实补充量」，从而保证任意并发下平均速率 ≤ ratePerSec。
// 突发语义保留：初始 tokens = capacity = ratePerSec，满桶时可突发消耗（与旧行为一致，测试不变）。
export class TokenBucket {
  constructor(ratePerSec) {
    this.ratePerSec = Number.isFinite(ratePerSec) && ratePerSec > 0
    ? Math.min(ratePerSec, 10000) // [P0-2] 上限 10000 req/s，防配置错误打爆目标
    : defaults.ratePerSec;
    this.capacity = this.ratePerSec;
    this.tokens = this.ratePerSec;
    this.last = Date.now();
    // 串行化队列：同一桶的 acquire 结算互斥，杜绝「多个等待者同一时刻放行」的突发
    this._chain = Promise.resolve();
  }

  // 获取一个令牌（不足则等待）。返回 promise；串行化保证并发调用下的真实限速。
  acquire() {
    const run = async () => {
      const now = Date.now();
      const elapsed = (now - this.last) / 1000;
      this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.ratePerSec);
      this.last = now;
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = ((1 - this.tokens) / this.ratePerSec) * 1000;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      // 等待期间令牌按速率持续补充：醒来后重新结算并扣除 1 个，不再直接清零
      // （原实现丢掉了等待期间累积的令牌，长等待下实际速率明显低于设定值）。
      const after = Date.now();
      this.tokens = Math.min(this.capacity, this.tokens + ((after - now) / 1000) * this.ratePerSec) - 1;
      this.last = after;
    };
    const p = this._chain.then(run, run);
    // 单个结算失败不阻断后续 acquire（setTimeout/算术不会抛，此为防御）
    this._chain = p.catch(() => {});
    return p;
  }
}

// 内置常见浏览器 User-Agent 池（原逻辑不变）
const DESKTOP_UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
];

// 移动端 UA 池（对标 sqlmap --mobile：CLI 将 --mobile 映射为 wafEvasion.randomUA='mobile'）
const MOBILE_UA_POOL = [
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
];

const UA_POOL = [...DESKTOP_UA_POOL, ...MOBILE_UA_POOL];

/**
 * 从 UA 池随机选取 User-Agent 字符串（WAF 规避 / 随机指纹）。
 * @param {'mobile'|'desktop'|undefined} kind 指定 'mobile' 则仅从移动端池取，否则从全池取
 * @returns {string} User-Agent 字符串
 */
export function pickRandomUA(kind) {
  const pool = kind === 'mobile' ? MOBILE_UA_POOL : UA_POOL;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ── 认证头合并（P2-8：头名黑名单）────────────────────────────────────────────
// 禁止调用者通过 auth.headers / headerParams 覆写以下头，防止请求走私/虚拟主机绕过
const FORBIDDEN_HEADERS = new Set([
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
  if (!auth) return h;
  if (auth.basic && auth.basic.username != null) {
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

// [P0-FIX] SOCKS/HTTP 代理 Agent 模块级缓存（按 proxyUrl 复用），避免每次请求重建 Agent
// 造成的 TCP+SOCKS5 握手开销（高量盲注提取下为主导成本）。
const _proxyAgentCache = new Map();

/**
 * 根据 proxyUrl 构建（或从缓存复用）代理 Agent 配置。
 * 支持 socks5:// 和 http:// 代理；按 proxyUrl 缓存以复用 keepAlive 长连接。
 * @param {string} [proxyUrl] 代理 URL
 * @returns {{proxy:boolean|object, httpAgent?:object, httpsAgent?:object}} axios 代理配置
 */
export function buildProxyAgent(proxyUrl) {
  if (!proxyUrl) return { proxy: false };
  // 命中缓存：复用已创建的 Agent（keepAlive 长连接复用）
  if (_proxyAgentCache.has(proxyUrl)) return _proxyAgentCache.get(proxyUrl);
  let conf;
  if (/^socks5?:\/\//i.test(proxyUrl)) {
    const agent = new SocksProxyAgent(proxyUrl, { keepAlive: true, maxSockets: AGENT_MAX_SOCKETS });
    conf = { proxy: false, httpAgent: agent, httpsAgent: agent };
  } else {
    const u = new URL(proxyUrl);
    conf = {
      proxy: {
        protocol: u.protocol.replace(':', ''),
        host: u.hostname,
        port: Number(u.port),
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
  }
  // 缓存上限：防止异常配置导致无界增长
  if (_proxyAgentCache.size > 16) _proxyAgentCache.delete(_proxyAgentCache.keys().next().value);
  _proxyAgentCache.set(proxyUrl, conf);
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

// 日志安全 URL（P2-5）：仅保留 scheme+host+path，query 值整体打码（防 payload/敏感参数进日志）
/**
 * 日志安全 URL（P2-5）：仅保留 scheme+host+path，query 整体打码（防 payload/敏感参数进日志）。
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

export class HttpClient {
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
    // [P1-FIX 2026-09-05] Cookie Jar（对标 sqlmap 自动会话保持）：scanId -> CookieJar，
    // 请求自动携带服务端 Set-Cookie 回发的会话，扫描退役时 clearJar 一并清理
    this._jars = new Map();
    this.disableKeepAlive = disableKeepAlive === true || defaults.disableKeepAlive === true;
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
    try { httpAgent.destroy?.(); } catch { /* ignore */ }
    try { httpsAgent.destroy?.(); } catch { /* ignore */ }
  }

  createBucket(scanId, ratePerSec) {
    const rps = Number.isFinite(ratePerSec) && ratePerSec > 0 ? ratePerSec : defaults.ratePerSec;
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
    return new Promise((resolve) => {
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
    // [P0-FIX] 提取路径（opts.maxContentLength）动态放大响应上限：默认 5MB，提取可至 50MB
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    return this.instance.request({
      method: opts.method || 'GET',
      url: opts.url,
      params: opts.params,
      data: opts.data,
      headers,
      timeout: timeoutMs,
      maxContentLength: maxBody,
      maxBodyLength: maxBody,
      ...proxyConf,
      ...(disableKA && !proxyConf.httpAgent ? { httpAgent: false, httpsAgent: false } : {}),
      maxRedirects: 0,
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...cfg,
    });
  }

  // 手动重定向跟随（P0-1）：最多 5 跳，每跳校验 Location 的 SSRF 策略
  // [P2-5] --ignore-redirects：redirects 传 0 时完全忽略 3xx（直接返回首跳跳转响应），
  // 对标 sqlmap --ignore-redirects（“不跟随重定向，直接返回 3xx”）。
  async _followRedirects(initial, opts, headers, proxyConf, timeoutMs, disableKA, redirects) {
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
        const nextUrl = new URL(current.headers.location, currentUrl).toString();
        await assertSafeHttpTarget(nextUrl); // 每跳重新校验（P0-1）
        // 跨域判定：hostname 或 protocol 变化即视为跨域（端口变化不强制剥离，避免误伤同站多端口）
        const u1 = new URL(currentUrl);
        const u2 = new URL(nextUrl);
        if (u1.hostname !== u2.hostname || u1.protocol !== u2.protocol) {
          if (activeHeaders === headers) activeHeaders = { ...headers }; // 首次跨域才克隆
          delete activeHeaders['Authorization'];
          delete activeHeaders['Cookie'];
          delete activeHeaders['Cookie2'];
          delete activeHeaders['Proxy-Authorization'];
        }
        // 303 → 强制 GET；301/302 对非 GET/HEAD 也降级为 GET（与浏览器一致，避免表单 POST 重放）
        let method = opts.method || 'GET';
        if (status === 303 || ((status === 301 || status === 302) && !['GET', 'HEAD'].includes(method))) {
          method = 'GET';
        }
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
  async _rawUndici(opts, headers, timeoutMs, pinnedLookup) {
    // DNS 钉死：优先用已校验 IP（防 rebinding）；无法钉死时回退常规解析（undici 自行解析）
    let lookup;
    if (pinnedLookup) {
      lookup = (hostname, o, cb) => pinnedLookup(hostname, o, cb);
    }
    const dispatchOpts = {
      method: String(opts.method || 'GET'),
      headers: { ...headers },
      body: opts.data,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      ...(lookup ? { connect: { ...(this.undiciAgent.opts?.connect || {}), lookup } } : {}),
    };
    const { statusCode, headers: resHeaders, body } = await undiciRequest(opts.url, {
      dispatcher: this.undiciAgent,
      method: dispatchOpts.method,
      headers: dispatchOpts.headers,
      body: dispatchOpts.body,
      headersTimeout: dispatchOpts.headersTimeout,
      bodyTimeout: dispatchOpts.bodyTimeout,
      ...(lookup ? { connect: { ...(this.undiciAgent.opts?.connect || {}), lookup } } : {}),
      ...(opts.signal ? { signal: opts.signal } : {}),
      // [P0-FIX] 手动重定向（逐跳 SSRF 校验 + 跨域剥离敏感头由 _followRedirectsH2 负责）：
      // undici 内置 maxRedirections 跟随的跳转目标不经过 assertSafeHttpTarget 校验、不钉 DNS，
      // 302 可跳内网/元数据地址（绕过出口 SSRF 防护）。置 0 关闭内置跟随。
      maxRedirections: 0,
    });
    // 体积上限：读流但截断超限（与 axios maxContentLength 语义近似，防 OOM）
    const chunks = [];
    let total = 0;
    const maxBody = opts.maxContentLength ?? MAX_BODY_BYTES;
    for await (const chunk of body) {
      total += chunk.length;
      if (total > maxBody) {
        chunks.push(Buffer.from(`[响应超限截断 ${total} 字节 > ${maxBody}]`));
        break;
      }
      chunks.push(chunk);
    }
    const data = Buffer.concat(chunks).toString('utf-8');
    return { status: statusCode, data, headers: resHeaders, isHttp2: true };
  }

  // [P0-FIX] HTTP/2 手动重定向跟随：undici 内置跟随已关闭（maxRedirections: 0），
  // 本方法逐跳跟随（最多 5 跳），每跳与 HTTP/1.1 路径一致地：
  //   ① assertSafeHttpTarget 校验跳转目标（防 302 跳内网/云元数据绕过出口 SSRF 防护）；
  //   ② 跨域（hostname/protocol 变化）时剥离 Authorization/Cookie 等凭据头（防凭据泄露到第三方域）；
  //   ③ 对跳转 URL 重新 DNS 钉死（防 rebinding）。
  // [P2-5] --ignore-redirects：redirects 传 0 时忽略 3xx（HTTP/2 路径与 HTTP/1.1 一致）
  async _followRedirectsH2(opts, headers, timeoutMs, redirects) {
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
        const nextUrl = new URL(current.headers.location, currentUrl).toString();
        await assertSafeHttpTarget(nextUrl); // 每跳重新校验（P0-1）
        // 跨域判定：hostname 或 protocol 变化即视为跨域（与 _followRedirects 一致）
        const u1 = new URL(currentUrl);
        const u2 = new URL(nextUrl);
        if (u1.hostname !== u2.hostname || u1.protocol !== u2.protocol) {
          if (activeHeaders === headers) activeHeaders = { ...headers };
          for (const k of Object.keys(activeHeaders)) {
            const lk = k.toLowerCase();
            if (lk === 'authorization' || lk === 'cookie' || lk === 'cookie2' || lk === 'proxy-authorization') {
              delete activeHeaders[k];
            }
          }
        }
        // 303 → 强制 GET；301/302 对非 GET/HEAD 也降级为 GET（与浏览器一致）
        let method = opts.method || 'GET';
        if (status === 303 || ((status === 301 || status === 302) && !['GET', 'HEAD'].includes(method))) {
          method = 'GET';
        }
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
    // P0-1：出口统一 SSRF 校验（直连模式 req.sql 无 URL，跳过）
    if (opts.url) {
      await assertSafeHttpTarget(opts.url).catch((e) => {
        if (e instanceof AppError) throw e;
        throw new AppError(ErrorCode.INVALID_PARAM, e.message || '目标 URL 校验失败');
      });
    }
    // [P0-3] DNS 钉死：从缓存取已校验 IP，传给请求层避免二次解析（防 DNS rebinding）
    // 仅在 assertSafeHttpTarget 已成功校验过该 URL 时生效
    const pinnedLookup = buildPinnedLookup(opts.url);
    // [P2-5] --ignore-redirects：跟随上限置 0 → 3xx 直接返回不跳转
    const redirectsLeft = opts.ignoreRedirects === true ? 0 : 5;
    // [sqlmap 对标] --reqrate：reqRate > 0 时覆盖 ratePerSec 作为 TokenBucket 速率
    const effectiveRate = (opts.reqRate && opts.reqRate > 0) ? opts.reqRate : opts.ratePerSec;
    const bucket =
      (opts.scanId && this.buckets.get(opts.scanId)) ||
      (Number.isFinite(effectiveRate) && effectiveRate > 0 ? this.bucketForRate(effectiveRate) : this.bucket);
    const proxyConf = buildProxyAgent(opts.proxy ?? defaults.proxy ?? false);
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
    let lastErr;
    for (let attempt = 0; attempt <= retry; attempt++) {
      // [⑮] abort 检查：signal 已取消时不再发新请求（重试循环防漏）
      if (opts.signal?.aborted) {
        const abortErr = new Error('请求已取消（扫描停止）');
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
          const abortErr = new Error('请求已取消（扫描停止）');
          abortErr.name = 'AbortError';
          abortErr.code = 'ERR_CANCELED';
          throw abortErr;
        }
      }
      try {
        await bucket.acquire();
        await applyJitter(opts.wafEvasion);
        // networkTiming（MERGED: perf 版）：从「令牌获取完成之后」计网络耗时，供时间盲注判定
        // 剔除限速排队等待（限速低时并发采样的排队时间会被旧 __elapsed 计入，导致基线虚高）。
        const t0Net = opts.networkTiming === true ? performance.now() : null;
        // [HTTP/2] 开启时走 undici（ALPN 协商 h2/h1.1）；否则沿用 axios HTTP/1.1（默认路径零变化）。
        // HTTP/2 路径同样手动跟随重定向（逐跳 SSRF 校验 + 跨域剥离凭据头，见 _followRedirectsH2）。
        let res;
        if (opts.http2 === true) {
          res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft);
        } else {
          const first = await this._rawRequest({ lookup: pinnedLookup }, opts, headers, proxyConf, timeoutMs, disableKA);
          res = await this._followRedirects(first, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft);
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
                headers['Authorization'] = rp.header;
                if (opts.http2 === true) {
                  res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft);
                } else {
                  const first2 = await this._rawRequest({ lookup: pinnedLookup }, opts, headers, proxyConf, timeoutMs, disableKA);
                  res = await this._followRedirects(first2, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft);
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
                res = await this._followRedirectsH2(opts, headers, timeoutMs, redirectsLeft);
              } else {
                const first2 = await this._rawRequest({ lookup: pinnedLookup }, opts, headers, proxyConf, timeoutMs, disableKA);
                res = await this._followRedirects(first2, opts, headers, proxyConf, timeoutMs, disableKA, redirectsLeft);
              }
            }
          }
        }
        if (t0Net !== null && res && typeof res === 'object') {
          // 非枚举属性：不污染任何 JSON 序列化/请求头透传路径
          Object.defineProperty(res, '__networkMs', {
            value: performance.now() - t0Net,
            enumerable: false,
            configurable: true,
            writable: true,
          });
        }
        return res;
      } catch (err) {
        lastErr = err;
        // [P0-FIX] AppError（SSRF 拦截 / 参数校验失败）是确定性的安全拒绝，重试多少次结果都一样，
        // 且每次重试都会重放整条重定向链（放大对禁止目标的探测）。必须立即抛出，不进入重试循环。
        if (err instanceof AppError) throw err;
        // [⑮] AbortError/CanceledError：扫描停止触发的请求取消，不重试直接抛出
        if (err.name === 'AbortError' || err.name === 'CanceledError' || err.code === 'ERR_CANCELED' || err.code === 'ABORT_ERR') {
          throw err;
        }
        const isTimeout = err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '');
        if (err && err.code && NON_RETRYABLE_CODES.has(err.code)) {
          // [P0-FIX] 不可重试错误但缓存中有多 IP 时：清除 DNS 缓存使后续请求重新解析、
          // 可能获得不同 IP。ECONNREFUSED 通常因 CDN 单 IP 宕机，60s 内不切 IP 会整段中断。
          if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
            const hostname = opts.url ? new URL(opts.url).hostname : null;
            if (hostname) dnsCache.delete(hostname);
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
            const abortErr = new Error('请求已取消（扫描停止）');
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

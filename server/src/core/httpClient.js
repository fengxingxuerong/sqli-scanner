import axios from 'axios';
import http from 'node:http';
import https from 'node:https';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { URL } from 'url';
import { defaults } from '../config/defaults.js';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';

// 令牌桶：控制全局发送速率（请求/秒），与并发池正交
class TokenBucket {
  /**
   * @param {number} ratePerSec 每秒允许的请求数
   */
  constructor(ratePerSec) {
    this.ratePerSec = ratePerSec;
    this.capacity = ratePerSec;
    this.tokens = ratePerSec;
    this.last = Date.now();
  }

  // 获取一个令牌（不足则等待）
  async acquire() {
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
    this.tokens = 0;
  }
}

// 内置常见浏览器 User-Agent 池（WAF 随机 UA 规避用）
const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
];

// 从 UA 池随机取一条
export function pickRandomUA() {
  return UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
}

/**
 * 合并认证相关请求头。
 * - auth.basic → Authorization: Basic base64(username:password)
 * - auth.cookie → 追加到已有 Cookie（与 Target.headerParams 合并后的 Cookie 叠加）
 * - auth.headers → 任意自定义头（对象）
 * 不传入 auth 时原样返回 headers。
 * @param {object} headers 已有请求头（含 Target.headerParams 合入的 Cookie/Header）
 * @param {object|null} auth { basic, cookie, headers }
 * @returns {object} 合并后的请求头
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
  if (auth.headers) {
    Object.assign(h, auth.headers);
  }
  return h;
}

/**
 * 构造 axios 代理配置。
 * - 空值 → { proxy: false }（不走代理，与 v1.0.0 行为一致）
 * - http(s):// → axios 原生 proxy 配置 { protocol, host, port }
 * - socks5:// / socks:// → { proxy:false, httpAgent, httpsAgent }（SocksProxyAgent）
 * @param {string|false|null} proxyUrl
 * @returns {object}
 */
export function buildProxyAgent(proxyUrl) {
  if (!proxyUrl) return { proxy: false };
  if (/^socks5?:\/\//i.test(proxyUrl)) {
    const agent = new SocksProxyAgent(proxyUrl);
    return { proxy: false, httpAgent: agent, httpsAgent: agent };
  }
  // HTTP / HTTPS 代理走 axios 原生 proxy 配置
  const u = new URL(proxyUrl);
  return {
    proxy: {
      protocol: u.protocol.replace(':', ''),
      host: u.hostname,
      port: Number(u.port),
    },
  };
}

// 请求间随机延时（WAF jitter 规避）。jitterMs<=0 时不休眠。
async function applyJitter(wafEvasion) {
  if (wafEvasion && wafEvasion.jitterMs > 0) {
    const ms = Math.floor(Math.random() * wafEvasion.jitterMs);
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// 固定请求间延时（对标 sqlmap --delay）：每次请求前休眠固定毫秒，与随机 jitter 正交、叠加生效。
// 在令牌桶之后、实际发包前施加，确保"限速 + 固定间隔"共同约束出站节奏。delayMs<=0 时不休眠。
async function applyFixedDelay(delayMs) {
  if (delayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

// HTTP 客户端封装：超时 + 指数退避重试 + 令牌桶限速 + 代理/认证/WAF 规避
// 所有出站请求必须经由本类，检测器/指纹/提取器不得自行 fetch/axios。
export class HttpClient {
  constructor() {
    this.bucket = new TokenBucket(defaults.ratePerSec);
    this.instance = axios.create({
      timeout: defaults.timeoutMs,
      maxRedirects: 5,
      // 不抛 4xx/5xx，交由检测器自行判断响应内容
      validateStatus: () => true,
    });
    // 连接复用（对标 sqlmap --keep-alive / --no-keep-alive）：
    // - 复用 agent（keepAlive=true）：多个请求共用 TCP 连接，降延迟/降低连接级指纹（更隐蔽）。
    // - 关闭 agent（keepAlive=false）：每次请求新建 TCP 连接（axios 默认 keepAlive=false），
    //   对"连接级速率限制 / 连接级指纹"敏感的目标更有用。
    // 复用 agent 关闭空闲超时自动回收（idleSocketTimeout=-1），避免长扫描中途连接被回收导致偶发 ECONNRESET。
    this.keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: Infinity, timeout: 60000, freeSocketTimeout: 30000 });
    this.keepAliveAgentHttps = new https.Agent({ keepAlive: true, maxSockets: Infinity, timeout: 60000, freeSocketTimeout: 30000 });
    this.closeAgent = new http.Agent({ keepAlive: false });
    this.closeAgentHttps = new https.Agent({ keepAlive: false });
    // 实例级默认是否复用连接（默认取模块 defaults；ScanManager 按本次扫描 config 经 fork/包装注入）。
    this.keepAlive = defaults.keepAlive !== false;
    // 实例级固定请求间延时（毫秒，对标 sqlmap --delay）。
    // 优先取每次 request 的 opts.requestDelayMs；否则取实例默认值（ScanManager 按本次扫描 config 注入）；
    // 再否则取模块 defaults（0）。
    this.requestDelayMs = defaults.requestDelayMs || 0;
  }

  /**
   * 派生一个扫描级客户端实例（对标 sqlmap 每次扫描独立的限速/连接策略）：
   * 共享本实例的 axios 实例与连接池 agent（连接复用，零额外开销），
   * 但**令牌桶独立**（每扫描独立限速，并发扫描互不拖慢、互不共享配额），
   * 且 requestDelayMs / keepAlive 按 config 覆盖（不再依赖全局单例的可变属性）。
   * @param {object|null} config 本次扫描 config（可含 ratePerSec / requestDelayMs / keepAlive）
   * @returns {HttpClient} 独立令牌桶的派生实例
   */
  fork(config = null) {
    const c = new HttpClient();
    // 共享无状态/连接池部分：axios 实例 + 4 个 agent（keepAliveAgent 关闭空闲回收，复用安全）
    c.instance = this.instance;
    c.keepAliveAgent = this.keepAliveAgent;
    c.keepAliveAgentHttps = this.keepAliveAgentHttps;
    c.closeAgent = this.closeAgent;
    c.closeAgentHttps = this.closeAgentHttps;
    // 独立令牌桶：ratePerSec 按本次扫描 config（缺省继承 defaults），并发扫描各自限速
    const rate = config && Number.isFinite(Number(config.ratePerSec)) && Number(config.ratePerSec) > 0
      ? Number(config.ratePerSec)
      : defaults.ratePerSec;
    c.bucket = new TokenBucket(rate);
    // 请求间固定延时 / 连接复用：按本次扫描 config 覆盖（保持与 withScanOverrides 同语义）
    if (config && config.requestDelayMs > 0) c.requestDelayMs = config.requestDelayMs;
    if (config && config.keepAlive === false) c.keepAlive = false;
    return c;
  }

  /**
   * 发送请求
   * @param {object} opts { method, url, params, data, headers, timeoutMs, retry, proxy, auth, wafEvasion }
   *   - proxy: 代理地址字符串（http:// 或 socks5://），为空走默认
   *   - auth: 认证配置 { basic, cookie, headers }
   *   - wafEvasion: { randomUA, jitterMs, obfuscate }（仅 randomUA/jitter 在此处施加，obfuscate 由调用方包裹 Payload）
   * @returns {Promise<import('axios').AxiosResponse>}
   */
  async request(opts) {
    const retry = opts.retry ?? defaults.retry;
    const timeoutMs = opts.timeoutMs ?? defaults.timeoutMs;
    // 代理配置（无 proxy 时返回 {proxy:false}，完全等价于 v1.0.0）
    const proxyConf = buildProxyAgent(opts.proxy ?? defaults.proxy ?? false);
    // 连接复用开关（对标 sqlmap --keep-alive / --no-keep-alive）：
    // 优先级：本次 opts.keepAlive > 实例默认（ScanManager 注入）> 模块 defaults。
    const keepAlive = opts.keepAlive ?? this.keepAlive ?? defaults.keepAlive !== false;
    // 是否走 HTTPS（决定用哪套 agent）。URL 可能为 http(s):// 字符串或 axios 对象。
    const isHttps = /^https:/i.test(opts.url || '');
    // 任意代理（SOCKS/HTTP）已自带 agent 或可让 axios 自行处理，此处不叠加 keepAlive agent，否则会冲突。
    // 仅在没有代理时按 keepAlive 选择连接复用 agent。
    const hasProxy = (opts.proxy ?? defaults.proxy) != null && (opts.proxy ?? defaults.proxy) !== false;
    let agentConf = {};
    if (!hasProxy) {
      if (keepAlive) {
        agentConf = isHttps ? { httpsAgent: this.keepAliveAgentHttps, httpAgent: this.keepAliveAgent } : { httpAgent: this.keepAliveAgent };
      } else {
        agentConf = isHttps ? { httpsAgent: this.closeAgentHttps, httpAgent: this.closeAgent } : { httpAgent: this.closeAgent };
      }
    }
    // 合并认证头（Target.headerParams 已合入 req.headers，此处叠加 auth 相关头）
    let headers = mergeAuthHeaders(opts.headers || {}, opts.auth ?? defaults.auth ?? null);
    // WAF 随机 UA：覆盖默认 UA（关闭时不动，保留 axios 默认）
    if (opts.wafEvasion && opts.wafEvasion.randomUA) {
      headers['User-Agent'] = pickRandomUA();
    }
    // 关闭连接复用时显式声明 Connection: close，确保服务端也在此次响应后关闭（与 agent 协同）。
    if (!keepAlive) headers['Connection'] = 'close';
    let lastErr;
    for (let attempt = 0; attempt <= retry; attempt++) {
      try {
        await this.bucket.acquire();
        // WAF 请求间随机延时（jitterMs=0 不休眠）
        await applyJitter(opts.wafEvasion);
        // 固定请求间延时（对标 sqlmap --delay）：delayMs>0 时每次请求前休眠固定毫秒
        // 优先级：本次 opts.requestDelayMs > 实例默认（ScanManager 注入）> 模块 defaults
        const delayMs = opts.requestDelayMs ?? this.requestDelayMs ?? defaults.requestDelayMs ?? 0;
        await applyFixedDelay(delayMs);
        const res = await this.instance.request({
          method: opts.method || 'GET',
          url: opts.url,
          params: opts.params,
          data: opts.data,
          headers,
          timeout: timeoutMs,
          ...agentConf,
          ...proxyConf,
        });
        return res;
      } catch (err) {
        lastErr = err;
        if (err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '')) {
          logger.warn(`HTTP 超时（第 ${attempt + 1} 次重试）：${opts.url}`);
          throw new AppError(ErrorCode.HTTP_TIMEOUT, '请求超时');
        }
        logger.warn(`HTTP 错误（第 ${attempt + 1} 次重试）：${err.message}`);
      }
    }
    throw new AppError(ErrorCode.HTTP_ERROR, lastErr?.message || 'HTTP 请求失败');
  }
}

/**
 * 扫描级客户端包装：把本次扫描的 requestDelayMs / keepAlive 注入到每个请求的 opts 中，
 * 避免 ScanManager 直接修改全局 HttpClient 单例属性（并发扫描互不干扰，最后一个扫描不再覆盖前者）。
 * 请求级显式传入的 opts.requestDelayMs / opts.keepAlive 仍优先（与 HttpClient.request 内优先级一致）。
 * 无覆盖配置时原样返回 inner（零包装、零开销）。
 * @param {object} inner 真实 httpClient（需暴露 request 方法）
 * @param {object|null} config 本次扫描 config（可含 requestDelayMs / keepAlive）
 * @returns {object} 包装客户端或 inner 本身
 */
export function withScanOverrides(inner, config) {
  const delay = config && config.requestDelayMs > 0 ? config.requestDelayMs : undefined;
  // keepAlive 默认 true（HttpClient 内部默认），仅显式 false 才需注入覆盖
  const keepAlive = config && config.keepAlive === false ? false : undefined;
  if (delay === undefined && keepAlive === undefined) return inner;
  return {
    request: (opts) =>
      inner.request({
        ...opts,
        requestDelayMs: opts.requestDelayMs ?? delay,
        keepAlive: opts.keepAlive ?? keepAlive,
      }),
  };
}

export const httpClient = new HttpClient();
export default httpClient;

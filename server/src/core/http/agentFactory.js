// ============================================================================
// http/agentFactory.js —— TLS/代理 Agent 组装工厂（httpClient 四期拆分 2026-09-30）
//
// 从 httpClient.js 迁出的模块级基础设施（零 this 耦合，耦合度实测见
// docs/大文件拆分-五刀复盘-2026-09-21.md 的方法）：axios 侧 keep-alive 单例、
// 按 {insecure, keepAlive} 组合缓存的 Agent 工厂、代理 Agent 缓存（HTTP/SOCKS）。
// httpClient.js 保留同名再导出（p2.test 等既有 import 路径不变）。
// ============================================================================
import http from 'node:http';
import https from 'node:https';
import { createHash } from 'node:crypto';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { AGENT_MAX_SOCKETS } from './agentPool.js';
import { parseProxyUrl, SOCKS_PROXY_SCHEMES } from './proxy.js';

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
// 单例导出：httpClient 的 axios 实例构造与 close() 生命周期管理要引用同一实例
// （共享 keep-alive 连接池是这两处语义的前提，不得各自新建）。
export { httpAgent, httpsAgent };

// ── [P1-FIX 2026-09-08 ①] TLS 校验开关的 Agent 组合缓存 ────────────────────────
// KEEPALIVE_AGENT_OPTS / httpAgent / httpsAgent 是模块级共享（服务所有扫描）：把
// rejectUnauthorized:false 挂到共享 httpsAgent 上，等于「一个自签目标关掉了全局证书校验」。
// 故按 {insecure, keepAlive} 组合另建 Agent 并缓存复用；默认组合（secure + keepAlive）仍复用
// 原共享实例（零行为变化），undici 侧另有 per-client 不安全 Agent（见 HttpClient.undiciAgentInsecure）。
const _tlsAgentCache = new Map();

/**
 * 取（或惰性建立）指定 TLS/keepAlive/mTLS 组合的 axios Agent 对。
 * @param {boolean} insecureTls true=关闭证书校验（自签/内网 CA 目标）
 * @param {boolean} [keepAlive] 是否挂 keep-alive（对齐 disableKeepAlive 语义）
 * @param {{cert:Buffer,key:Buffer}|null} [mtls] mTLS 客户端证书（sqlmap --cert 语义）：
 *   挂在 httpsAgent 的 cert/key 上；缓存键掺证书指纹，不同证书不串池。
 * @returns {{httpAgent?:object, httpsAgent?:object}}
 */
export function agentsForTls(insecureTls, keepAlive = true, mtls = null) {
  const fp = mtls ? createHash('sha256').update(mtls.cert).digest('hex').slice(0, 12) : '';
  const key = `${insecureTls ? 'insecure' : 'secure'}|${keepAlive ? 'ka' : 'noka'}|${fp}`;
  const hit = _tlsAgentCache.get(key);
  if (hit) return hit;
  /** @type {any} */ let conf;
  if (!insecureTls && !mtls) conf = keepAlive ? { httpAgent, httpsAgent } : {};
  else {
    const base = keepAlive ? { ...KEEPALIVE_AGENT_OPTS } : { keepAlive: false, maxSockets: AGENT_MAX_SOCKETS };
    conf = {
      httpAgent: new http.Agent(base),
      httpsAgent: new https.Agent({
        ...base,
        // 只有 https Agent 需要关校验（http 通道无 TLS）；mTLS 证书同理只挂 https
        ...(insecureTls ? { rejectUnauthorized: false } : {}),
        ...(mtls ? { cert: mtls.cert, key: mtls.key } : {}),
      }),
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

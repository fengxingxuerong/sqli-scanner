// ============================================================================
// core/netProbe.js —— 本机联网自检（对标 sqlmap --check-internet）
//
// ── 它要回答的问题 ───────────────────────────────────────────────────────────
// 扫描报「目标不可达」时，可能是目标挂了，也可能是**本机压根没网**。两者对使用者的
// 含义完全不同（前者该等，后者该修网络），但引擎此前把它们混成同一条 ECONNREFUSED /
// ENOTFOUND。这个探测只做一件事：给「本机有没有网」一个可判的答案。
//
// ── 为什么用 TCP:53 而不是 HTTP ──────────────────────────────────────────────
// · 不产生 HTTP 语义（不碰目标、不留 UA、不触发任何 WAF 规则）；
// · DNS 端口几乎不被企业防火墙拦（80/443 常被代理或拦截页接管，探测结果反而失真）；
// · 代价是只证明「到 DNS 的 TCP 通」，不等于「目标可达」——这正是本探测的口径边界，
//   它只用来区分「本机断网」与「目标不可达」，**不能**用来判断目标状态。
//
// ── 边界（写进代码，避免被当成能力声明）──────────────────────────────────────
// · 失败只**警告**不阻断：内网/离线靶场环境本来就访问不了公网，阻断会把正常场景判死。
// · 默认探测两个地址（Cloudflare + 阿里 DNS），任一通即算有网——单点被拦不误报。
// ============================================================================
import net from 'node:net';

/** 默认探测目标：两个不同运营商的 DNS，避免单点被墙/被拦导致误报 */
const DEFAULT_PROBES = ['1.1.1.1:53', '223.5.5.5:53'];

/**
 * 单点 TCP 连通性探测。
 * @param {string} host 主机
 * @param {number} port 端口
 * @param {number} timeoutMs 超时
 * @returns {Promise<boolean>} 是否连上
 */
function tcpOpen(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(v);
    };
    const socket = net.connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

/**
 * 本机联网自检：任一探测点连通即判「有网」。
 * @param {{probes?: string[], timeoutMs?: number}} [opts] probes 形如 `host:port`
 * @returns {Promise<{ok: boolean, via: string|null, tried: string[]}>} ok=有网；via=命中的探测点
 */
export async function probeInternet(opts = {}) {
  const probes = opts.probes ?? DEFAULT_PROBES;
  const timeoutMs = opts.timeoutMs ?? 1500;
  for (const p of probes) {
    const i = p.lastIndexOf(':');
    if (i <= 0) continue;
    const host = p.slice(0, i);
    const port = Number(p.slice(i + 1));
    if (!Number.isFinite(port)) continue;
    if (await tcpOpen(host, port, timeoutMs)) return { ok: true, via: p, tried: probes };
  }
  return { ok: false, via: null, tried: probes };
}

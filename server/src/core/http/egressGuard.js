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
import { logger } from '../logger.js';
// [P0-FIX 2026-09-29] IP 解析与前缀比较的唯一真源（字节级，不做字符串前缀匹配）。
// 与 scopeGuard 共用 —— 本项目反复吃过「同一判据两份实现，一份修了另一份没修」的亏。
import { ipv6ToBytes, bytesInPrefix, IPV6_BLOCKS, embeddedIpv4 } from './ipBytes.js';

// ── SSRF 防护（P0-1）────────────────────────────────────────────────────────
// 分层策略（按 env 决定拒绝集合）。IPv4 与 IPv6 **逐层对齐**（各段对应关系写在下面）：
//   · 基础层（无条件拒绝，代理模式下也不放行）：对扫描器自身没有任何合法扫描价值，
//     是 SSRF 最高价值目标。
//       IPv4：0.0.0.0/8、链路本地 169.254.0.0/16（含云元数据 169.254.169.254）、
//             组播 224/4、保留 240/4、文档段/基准测试段、CGNAT 100.64/10
//       IPv6：::（未指定）、fe80::/10（链路本地，含云元数据 IPv6 变体）、
//             fec0::/10（RFC 3879 废弃站点本地）、ff00::/8（组播）、
//             2001:db8::/32（文档段）、fd00:ec2::/32（AWS IMDS 的 IPv6 端点 ——
//             它落在 ULA 内，必须单列，否则会随"ULA 在代理模式放行"一起被放掉）、
//             64:ff9b::/96 与 64:ff9b:1::/48（NAT64，可内嵌内网 IPv4）、
//             ::/96 中 IPv4-compatible 的残余部分
//   · 严格层（SSRF_STRICT=1 时追加；HOST 为非回环时自动进入）：面向「引擎暴露在非回环
//     接口」的部署（容器/局域网/公网）。
//       IPv4：回环 127.0.0.0/8、私网 10/8、172.16/12、192.168/16
//       IPv6：回环 ::1、ULA fc00::/7
//   · IPv4-mapped（::ffff:0:0/96）：**按内嵌 IPv4 走完整规则**（含 hardOnly 语义）。
//     `::ffff:7f00:1` 就是 127.0.0.1、`::ffff:a9fe:a9fe` 就是 169.254.169.254。
//     注意 URL 会把 `[::ffff:127.0.0.1]` 归一成 `[::ffff:7f00:1]`，两条路径必须同结论。
//   · 显式放行：SSRF_ALLOW_CIDRS=1.2.3.0/24,... 逐段放行（优先级最高，供内部授权目标/演练用）；
//     SSRF_ALLOW_PRIVATE=1 只豁免**严格层**（回环/私网），不豁免上面那条基础层——
//     2026-09-28 接口靶场实测出这条不一致并把口径改正（详见 isBlockedIpv4 内注释）。
//
// ⚠️ 历史教训（2026-09-29）：上面这段承诺最初只按 IPv4 写、也只按 IPv4 验证过，IPv6 分支
// 用的是**字符串前缀匹配**（`/^f[cd]$/.test(首段)`），对任何压缩写法都不命中 ⇒
// `::ffff:7f00:1`、`fe80::1`、`fd00::1`、`fd00:ec2::254` 在 SSRF_STRICT=1 下全部放行。
// 现在 IPv6 一律走 `ipBytes.js` 的**字节级前缀比较**，专项回归见 tests/ssrf.ipv6.test.js
// （9 条目标 + hardOnly 路径 + 对称性 + 防过度拦截）。
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

// ── [P0-FIX 2026-09-29] IPv6 判定：**字节级前缀比较**（旧实现是字符串前缀匹配，被绕过）
// ----------------------------------------------------------------------------
// 实测（SSRF_STRICT=1，即 HOST!=127.0.0.1 的生产姿态）下列目标**全部放行**：
//     http://[::ffff:7f00:1]:4567/   IPv4-mapped 回环（docker 单端口部署下就是引擎自身）
//     http://[fe80::1]/              链路本地
//     http://[fd00::1]:4567/         ULA 私网
//     http://[fd00:ec2::254]/        AWS IMDS 的 IPv6 端点（云元数据）
// 根因有三，全部在旧实现里：
//   ① `ipv6InPrefix` 对 `::ffff:<点分>` 无条件 `return isBlockedIpv4(...)` —— 无视调用方
//      问的是哪个前缀（越权回答）；而十六进制写法 `::ffff:7f00:1` 不匹配那条正则，落到
//      `bits===128` 分支与 `'::1'` 比较 ⇒ 恒 false。
//   ② ULA/链路本地用 `/^f[cd]$/`、`/^fe[89ab]$/` 匹配**首段字符串** ——
//      `fd00::1`、`fe80::1` 的首段是 `fd00`/`fe80`，永远不命中（连注释里举的例子都没拦住）。
//   ③ `hardOnly` 在严格层判定**之前** `return false`，使"ULA / ::1 永远拒绝"的注释承诺
//      在代理模式下失效。
// 现在一律：解析成 16 字节 → 按 bits 比较前缀。解析与比较的唯一真源在 `ipBytes.js`。
const IPV6 = IPV6_BLOCKS;

/**
 * IPv6 黑名单判定。
 *
 * 判定顺序刻意显式（每条拒绝理由都能指出来源），并与 IPv4 侧**逐段对齐**：
 *   · 「无条件拒绝段」= 对扫描器零合法价值 ⇒ 代理模式（hardOnly）也不放行；
 *   · 「等价私网」（ULA ↔ RFC1918、::1 ↔ 127/8）= 授权打内网靶站的合法用途
 *     ⇒ 仅在 hardOnly 下放行给代理侧判定（与 isBlockedIpv4 的严格层同语义）。
 * @param {string} ip
 * @param {boolean} hardOnly 硬底线模式（代理路径）
 */
function isBlockedIpv6(ip, hardOnly = false) {
  const bytes = ipv6ToBytes(ip);
  if (!bytes) return false; // 非法 IPv6 ⇒ net.isIP 已先行过滤，此处不越权判定

  // ipv6ToBytes(b.prefix) 是常量字面量，解析失败会得 null ⇒ bytesInPrefix 按 fail-closed 返回 false
  const inBlock = (b) => bytesInPrefix(bytes, ipv6ToBytes(b.prefix), b.bits);

  // ① 无条件拒绝段（与 IPv4 基础层一一对应）
  if (inBlock(IPV6.UNSPECIFIED)) return true;        // :: ↔ 0.0.0.0
  if (inBlock(IPV6.LINK_LOCAL)) return true;         // fe80::/10 ↔ 169.254.0.0/16（含云元数据 IPv6 变体）
  if (inBlock(IPV6.SITE_LOCAL)) return true;         // fec0::/10：RFC 3879 已废弃的站点本地
  if (inBlock(IPV6.MULTICAST)) return true;          // ff00::/8 ↔ 224.0.0.0/4
  if (inBlock(IPV6.DOCUMENTATION)) return true;      // 2001:db8::/32 ↔ 192.0.2.0/24 等文档段
  // 云元数据 IPv6：AWS IMDS 的 `fd00:ec2::254`。落在 ULA 里，若不单列就会被
  // 「ULA 在代理模式下放行」一起放掉 —— 而云元数据恰恰是 SSRF 最高价值目标，
  // 不能因为"它长得像私网"就按私网对待（IPv4 侧同理：169.254.169.254 属基础层，不吃 ALLOW_PRIVATE）。
  if (inBlock(IPV6.CLOUD_METADATA)) return true;     // fd00:ec2::/32
  // NAT64：可把内网 IPv4 嵌进来（`64:ff9b::7f00:1` = 127.0.0.1），必须整段拒绝，
  // 否则它是绕过全部 IPv4 段判定的现成通道。
  if (inBlock(IPV6.NAT64)) return true;              // 64:ff9b::/96
  if (inBlock(IPV6.NAT64_LOCAL)) return true;        // 64:ff9b:1::/48
  // ② IPv4-mapped（::ffff:0:0/96）：**交给完整 IPv4 规则**（含 hardOnly 语义）。
  //    `::ffff:7f00:1` 就是 127.0.0.1、`::ffff:a9fe:a9fe` 就是 169.254.169.254（云元数据）。
  //    这一步是 real-world 最常被漏掉的绕过点：它为十六进制写法，字符串前缀匹配看不见。
  if (inBlock(IPV6.IPV4_MAPPED)) {
    const v4 = embeddedIpv4(ip);
    if (v4) return isBlockedIpv4(v4.join('.'), hardOnly);
    return true; // 解析不出内嵌 v4 的 mapped 形态：宁可拒绝
  }
  // ③ ::/96 里剩下的（IPv4-compatible，RFC 4291 已废弃）：`::7f00:1` 这类写法
  //    能表达 127.0.0.1 却既不进 mapped 分支、也不是普通公网地址 ⇒ 整段拒绝。
  //    注意 ::1（回环）也在此段内，但它在下面 ④ 单独判定以与 IPv4 的 127/8 对齐。
  const isLoopback = inBlock(IPV6.LOOPBACK);
  const isV4Compat = bytesInPrefix(bytes, ipv6ToBytes('::'), 96);
  if (isV4Compat && !isLoopback) return true;

  // ④ 等价私网/回环（严格层）：与 IPv4 侧**逐层对齐**
  //    · 严格层（回环/私网）仅在 POLICY.strict 下拒绝 —— 非严格模式是为「本机/内网靶站」
  //      留的开发姿态，IPv4 的 127/8、10/8、192.168/16 就是这么做的；IPv6 必须同语义，
  //      否则同一个 localhost 会因解析成 127.0.0.1 还是 ::1 得到两种结论（实测踩到）。
  //    · ULA（fc00::/7）保持**无条件拒绝**，与本文件的历史注释一致（"永远拒绝"）。
  //      它比 IPv4 私网更严，不是漏洞；改严→宽的放松不在本次修复范围。
  if (hardOnly) return false;
  if (POLICY.strict) {
    if (inBlock(IPV6.ULA)) return true;   // fc00::/7 ↔ RFC1918
    if (isLoopback) return true;          // ::1 ↔ 127.0.0.0/8
  } else if (inBlock(IPV6.ULA)) {
    return true;                          // 非严格模式仍拒 ULA（历史语义，见上）
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
  // 显式逐段放行优先（硬底线模式不受放行清单影响）。
  // ⚠ SSRF_ALLOW_PRIVATE **不在这一层**：见下方"基础层"之后的处理。
  //   原实现在这里 `else if (POLICY.allowAll) return false;`，于是 ALLOW_PRIVATE=1 会把
  //   0.0.0.0/8、169.254.0.0/16（云元数据）、组播/保留段一起放行——与这个文件开头
  //   「基础层（无条件拒绝）：…对扫描器自身没有任何合法扫描价值」的承诺直接矛盾（实测：
  //   ALLOW_PRIVATE=1 下 POST /scan/start 指向 169.254.169.254 拿到 scanId 并真的发请求）。
  //   ALLOW_PRIVATE 的合法用途是"我要打内网靶站"（回环/私网，属严格层），
  //   不是"我要打元数据"；真要把某个元数据段纳入授权，请显式写进 SSRF_ALLOW_CIDRS。
  if (!hardOnly && POLICY.allowCidrs.some((cidr) => {
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
  // SSRF_ALLOW_PRIVATE=1：放行回环/私网（打内网靶站的合法用途），
  // 但上面那批基础层地址已经被无条件拒绝，不受本开关影响。
  if (POLICY.allowAll) return false;
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
  if (v === 6) return isBlockedIpv6(ip, hardOnly);
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

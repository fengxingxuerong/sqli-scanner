// ============================================================================
// core/http/ipBytes.js —— IP 字面量 → 字节数组 与 前缀比较（**唯一真源**）
//
// 为什么独立成模块（2026-09-29 实测，SSRF 防护被绕过的根因）
// ----------------------------------------------------------------------------
// SSRF 的目标校验（`egressGuard.js`）需要判断「这个 IP 是不是回环/链路本地/ULA/元数据段」，
// 而历史的做法是**字符串前缀匹配**：
//     if (prefix === 'fc00::' && bits === 7) {
//       const first = lower.split(':')[0] || '';
//       return /^f[cd]$/.test(first);        // ← 只认 "fc"/"fd" 两个字符的首段
//     }
// 这个写法对**任何压缩写法**都失效：`fd00::1` 的首段是 `fd00`，`fe80::1` 是 `fe80` ——
// 正则都不命中。实测（SSRF_STRICT=1）下列目标全部放行：
//     http://[::ffff:7f00:1]:4567/    ← IPv4-mapped 回环（docker 单端口部署下即引擎自身）
//     http://[fe80::1]/               ← 链路本地
//     http://[fd00::1]:4567/          ← ULA 私网
//     http://[fd00:ec2::254]/         ← AWS IMDS 的 IPv6 端点（云元数据）
// 同时 `ipv6InPrefix` 对 `::ffff:<点分>` 会**越界返回**（无视调用方问的是哪个前缀），
// 于是「校验用归一前的串、请求用归一后的地址」之间裂开一道缝。
//
// 结论：判断 IP 属于哪个段**必须按字节比较**，字符串前缀匹配是错的工具。
// scopeGuard 早就有正确的实现（`ipv6ToBytes`），但它与 egressGuard 各写一份 ——
// 本项目反复吃过「同一判据多份实现，一份修了另一份没修」的亏（见 duplicateSymbol.guard）。
// 故此处收敛为唯一真源，两端共用；`duplicateSymbol.guard.test.js` 会钉住"不得再开副本"。
//
// 解析规则（严格，宁可返回 null 也不猜）
// ----------------------------------------------------------------------------
//   · IPv4：四段点分十进制，每段 0-255
//   · IPv6：支持 `::` 缩写、内嵌 IPv4（点分或十六进制两种写法）、大写、尾部 zone id(`%eth0`)
//   · **点分段必须是最后一段**，且长度恰为 4，否则整串判 null ——
//     绝不"丢掉不认识的段继续算"（历史 `ipv6ToBytes` 对 `::ffff:127.0.0.1` 就是把点分四段
//     整段丢弃，解析出 `::ffff:0:0`，一个**语义错误但不报错**的结果）
// ============================================================================

/**
 * IPv4 字面量 → 4 字节。非法返回 null。
 * @param {string} ip
 * @returns {number[]|null}
 */
export function ipv4ToBytes(ip) {
  const parts = String(ip ?? '').split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    bytes.push(n);
  }
  return bytes;
}

const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

/**
 * IPv6 字面量 → 16 字节。非法返回 null。
 * @param {string} ip
 * @returns {number[]|null}
 */
export function ipv6ToBytes(ip) {
  // zone id（fe80::1%eth0）：只允许「地址%标识」两段，且标识必须是常规字符 ——
  // 不能简单 `split('%')[0]` 了事：那样 `::%eth0:1` 会被截成 `::`（一个"看起来合法"的
  // 未指定地址），把非法输入静默洗成合法值正是安全判据里最危险的容错形态。
  const parts = String(ip ?? '').trim().split('%');
  if (parts.length > 2) return null;
  if (parts.length === 2 && !/^[A-Za-z0-9_.-]+$/.test(parts[1])) return null;
  const raw = parts[0];
  if (!raw.includes(':')) return null;

  const doubleColon = raw.split('::');
  if (doubleColon.length > 2) return null; // 只允许一个 `::`

  const parseGroups = (segment) => {
    if (!segment) return [];
    const out = [];
    const groups = segment.split(':');
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      // 内嵌 IPv4：必须是**最后一段**且写成点分四点（`::ffff:127.0.0.1`）
      if (g.includes('.')) {
        if (i !== groups.length - 1) return null;
        const v4 = ipv4ToBytes(g);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
        continue;
      }
      if (!HEX_GROUP.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const head = parseGroups(doubleColon[0]);
  if (head === null) return null;

  let words;
  if (doubleColon.length === 1) {
    words = head;
    if (words.length !== 8) return null; // 无 `::` 时必须写满 8 段
  } else {
    const tail = parseGroups(doubleColon[1]);
    if (tail === null) return null;
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    words = [...head, ...new Array(fill).fill(0), ...tail];
  }
  if (words.length !== 8) return null;

  const bytes = [];
  for (const w of words) {
    if (!Number.isInteger(w) || w < 0 || w > 0xffff) return null;
    bytes.push((w >> 8) & 0xff, w & 0xff);
  }
  return bytes;
}

/**
 * 按**字节**比较前缀：a 的前 bits 位是否与 prefix 相同。
 * 两侧都接受 null/undefined（解析失败的产物）并按 **fail-closed** 返回 false ——
 * 调用点常写 `bytesInPrefix(bytes, ipv6ToBytes('fe80::'), 10)`，而 ipv6ToBytes 可能返回 null；
 * 与其在每个调用点加断言，不如让本函数显式承担"解析不出来就不算命中"的语义。
 * @param {number[]|null|undefined} a 被测地址字节
 * @param {number[]|null|undefined} prefix 期望前缀字节（常量字面量解析结果）
 * @param {number} bits 前缀长度（0-128）
 * @returns {boolean}
 */
export function bytesInPrefix(a, prefix, bits) {
  if (!Array.isArray(a) || !Array.isArray(prefix)) return false;
  const n = Number(bits);
  if (!Number.isInteger(n) || n < 0 || n > a.length * 8) return false;
  const fullBytes = Math.floor(n / 8);
  const restBits = n % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== prefix[i]) return false;
  }
  if (restBits) {
    const mask = (0xff << (8 - restBits)) & 0xff;
    if (((a[fullBytes] ?? 0) & mask) !== ((prefix[fullBytes] ?? 0) & mask)) return false;
  }
  return true;
}

/** 从点分/十六进制前缀字符串构造 IPv6 前缀字节（供声明式段表使用） */
export function prefixBytesFromString(s) {
  return ipv6ToBytes(s);
}

// ── 网段表（声明式单一来源）─────────────────────────────────────────────────
// 每条 = { prefix, bits, name }。判定一律走 bytesInPrefix，不做任何字符串前缀匹配。
/** IPv6 网段 */
export const IPV6_BLOCKS = {
  /** ::/128 未指定地址 */
  UNSPECIFIED: { prefix: '::', bits: 128, name: 'unspecified' },
  /** ::1/128 回环 */
  LOOPBACK: { prefix: '::1', bits: 128, name: 'loopback' },
  /** ::ffff:0:0/96 IPv4-mapped（内嵌 IPv4 一律按 IPv4 规则判，不在此单列） */
  IPV4_MAPPED: { prefix: '::ffff:0:0', bits: 96, name: 'ipv4-mapped' },
  /** fe80::/10 链路本地（含云元数据 IPv6 变体） */
  LINK_LOCAL: { prefix: 'fe80::', bits: 10, name: 'link-local' },
  /** fec0::/10 已废弃的站点本地（RFC 3879）—— 同样不给扫描器任何合法价值 */
  SITE_LOCAL: { prefix: 'fec0::', bits: 10, name: 'site-local-deprecated' },
  /** fc00::/7 唯一本地地址（ULA，等价私网） */
  ULA: { prefix: 'fc00::', bits: 7, name: 'ula' },
  /** ff00::/8 组播 */
  MULTICAST: { prefix: 'ff00::', bits: 8, name: 'multicast' },
  /** 2001:db8::/32 文档段 */
  DOCUMENTATION: { prefix: '2001:db8::', bits: 32, name: 'documentation' },
  /** fd00:ec2::/32 —— AWS IMDS 的 IPv6 端点段。单列的原因见 egressGuard 的判定顺序注释：
   *  它落在 ULA(fc00::/7) 内，若不单列就会随"ULA 在代理模式下放行"一起放掉，
   *  而云元数据属于"零合法价值"那一类（与 IPv4 的 169.254.169.254 同级）。 */
  CLOUD_METADATA: { prefix: 'fd00:ec2::', bits: 32, name: 'cloud-metadata-ipv6' },
  /** 64:ff9b::/96 NAT64（可把内网 IPv4 嵌进来，2001:db8 之外最常被忽略的一条） */
  NAT64: { prefix: '64:ff9b::', bits: 96, name: 'nat64' },
  /** 64:ff9b:1::/48 本地用途 NAT64 */
  NAT64_LOCAL: { prefix: '64:ff9b:1::', bits: 48, name: 'nat64-local' },
  /** ::/96 IPv4-compatible（已废弃，但解析器仍可能接受） */
  IPV4_COMPAT: { prefix: '::', bits: 96, name: 'ipv4-compatible-deprecated' },
};

/**
 * 内嵌 IPv4 提取：`::ffff:1.2.3.4` / `::ffff:0102:0304` → [1,2,3,4]。
 * 这是「IPv4 规则必须作用于内嵌 IPv4」的入口 —— 少了它，`::ffff:7f00:1` 这类写法
 * 就会以"某个 IPv6 地址"的身份绕过所有 IPv4 段判定。
 * @param {string} ip
 * @returns {number[]|null}
 */
export function embeddedIpv4(ip) {
  const bytes = ipv6ToBytes(ip);
  if (!bytes) return null;
  const isMapped = bytesInPrefix(bytes, ipv6ToBytes('::ffff:0:0'), 96);
  const isCompat = bytes.slice(0, 12).every((b) => b === 0);
  if (!isMapped && !isCompat) return null;
  return bytes.slice(12, 16);
}

export default {
  ipv4ToBytes, ipv6ToBytes, bytesInPrefix, prefixBytesFromString,
  IPV6_BLOCKS, embeddedIpv4,
};

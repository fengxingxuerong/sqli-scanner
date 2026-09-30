// ============================================================================
// tests/ssrf.ipv6.test.js —— SSRF 防护的 IPv6 专项用例（9 条 + hardOnly 路径）
//
// 为什么单独一个文件（2026-09-29 实测事故）
// ----------------------------------------------------------------------------
// `egressGuard.js` 的 SSRF 承诺是「基础层无条件拒绝：0.0.0.0/8、链路本地 169.254.0.0/16
// （含云元数据 169.254.169.254）、组播/保留/文档段；严格层拒绝回环/私网」。但那段承诺
// **只按 IPv4 写、也只用 IPv4 验证过**，IPv6 分支是字符串前缀匹配：
//     if (prefix === 'fc00::' && bits === 7) return /^f[cd]$/.test(lower.split(':')[0]);
// 对任何**压缩写法**都不命中（`fd00::1` 首段是 `fd00`，不是 `fd`）。SSRF_STRICT=1 下实测：
//     ✅ 放行  http://[::ffff:7f00:1]:4567/      IPv4-mapped 回环（docker 单端口下=引擎自身）
//     ✅ 放行  http://[fe80::1]/                 链路本地
//     ✅ 放行  http://[fd00::1]:4567/            ULA 私网
//     ✅ 放行  http://[fd00:ec2::254]/           AWS IMDS 的 IPv6 端点（云元数据）
// 更细的一层：`ipv6InPrefix` 对 `::ffff:<点分>` 会**越权返回** `isBlockedIpv4(...)`，
// 无视调用方问的是哪个前缀；而 `new URL('http://[::ffff:127.0.0.1]/')` 归一成
// `[::ffff:7f00:1]` ⇒ **校验用归一前的串、请求用归一后的地址**，中间裂开一道缝。
//
// 本文件就是把这 9 条钉成回归：**任何一条在修复前都必须失败**（否则用例没有牙）。
// 用例如有增删，必须同时说明「它对应上面哪一条绕过」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';

// 生产姿态：HOST!=127.0.0.1 时 egressGuard 自动把 POLICY.strict 置真。
//
// ⚠️ 两个必须显式控制的输入（本文件断言的是"生产姿态"，不能依赖环境凑巧对）：
//   ① `SSRF_STRICT=1`：本机跑 `node --test <file>` 时 HOST 未设 ⇒ 不会自动进严格层。
//   ② **必须清掉 `SSRF_ALLOW_PRIVATE`**：`.env.test` 里它是 `1`（全仓大量用 127.0.0.1
//      做 mock，需显式放行私网），而 POLICY 是**模块加载时求值**的 —— 带着它导入，
//      `allowAll=true` 会让「等价私网」整层失效，于是 `::ffff:127.0.0.1`（走 IPv4 规则）
//      被判为可放行。实测表现：本文件单独跑全绿，跑 `npm test`（含 --env-file=.env.test）
//      时 2 条红 —— 这种「换个命令就变绿」的假绿比红更危险，故在此显式清除，
//      并在下面用一条前置断言证明"策略确实是生产姿态"（前提不成立就立刻失败，而不是静默通过）。
//
// cache-busting 动态 import：POLICY 在模块加载时固化，故取一份独立实例（本仓既有做法，
// 见 exploitRoutes.edge.test.js / reportAI.service.test.js）。
const _savedSsrfEnv = {
  SSRF_STRICT: process.env.SSRF_STRICT,
  SSRF_ALLOW_PRIVATE: process.env.SSRF_ALLOW_PRIVATE,
  SSRF_ALLOW_CIDRS: process.env.SSRF_ALLOW_CIDRS,
};
process.env.SSRF_STRICT = '1';
delete process.env.SSRF_ALLOW_PRIVATE;
delete process.env.SSRF_ALLOW_CIDRS;

const { isBlockedIp, assertSafeHttpTarget } = await import('../src/core/http/egressGuard.js?ssrf-ipv6=1');
const { ipv6ToBytes, bytesInPrefix, embeddedIpv4, IPV6_BLOCKS } = await import('../src/core/http/ipBytes.js?ssrf-ipv6=1');

// 恢复环境（本文件进程内可能还有其它断言；模块实例已固化，不受影响）
if (_savedSsrfEnv.SSRF_STRICT !== undefined) process.env.SSRF_STRICT = _savedSsrfEnv.SSRF_STRICT;
if (_savedSsrfEnv.SSRF_ALLOW_PRIVATE !== undefined) process.env.SSRF_ALLOW_PRIVATE = _savedSsrfEnv.SSRF_ALLOW_PRIVATE;
if (_savedSsrfEnv.SSRF_ALLOW_CIDRS !== undefined) process.env.SSRF_ALLOW_CIDRS = _savedSsrfEnv.SSRF_ALLOW_CIDRS;

test('前置：被测实例必须处于生产姿态（严格层生效、无显式放行）', () => {
  // 这条不是"多此一举"，它是本文件全部结论的前提：
  // 若策略被环境改成宽松（如 .env.test 的 SSRF_ALLOW_PRIVATE=1 生效），
  // 下面那些用例会**静默变成假绿**——而 SSRF 用例的假绿意味着"以为拦住了，其实没有"。
  assert.equal(isBlockedIp('127.0.0.1'), true, '严格层必须生效：生产姿态下 127.0.0.1 应被拦（否则 POLICY 被放行开关放宽了）');
  assert.equal(isBlockedIp('10.0.0.1'), true, '严格层必须生效：10.0.0.1 应被拦');
  assert.equal(isBlockedIp('169.254.169.254'), true, '基础层必须生效：云元数据应被拦');
});

/** 9 条 IPv6 用例：每条都对应审计里实测到的一条绕过或一个必须拦的段 */
const BLOCKED_IPV6 = [
  { ip: '::1', url: 'http://[::1]:4567/health', why: '回环（IPv6 正字法）' },
  { ip: '0:0:0:0:0:0:0:1', url: 'http://[0:0:0:0:0:0:0:1]/', why: '回环（完全展开写法，与 ::1 必须同结论）' },
  { ip: '::ffff:127.0.0.1', url: 'http://[::ffff:127.0.0.1]/', why: 'IPv4-mapped 回环（点分写法）' },
  { ip: '::ffff:7f00:1', url: 'http://[::ffff:7f00:1]:4567/health', why: 'IPv4-mapped 回环（十六进制写法）——URL 归一化后的真实形态，旧实现在此放行' },
  { ip: 'fe80::1', url: 'http://[fe80::1]/', why: '链路本地（旧的 /^fe[89ab]$/ 匹配首段，fe80 不命中）' },
  { ip: 'fc00::1', url: 'http://[fc00::1]/', why: 'ULA（旧的 /^f[cd]$/ 不命中 fc00）' },
  { ip: 'fd00::1', url: 'http://[fd00::1]:4567/', why: 'ULA（同上，fd00 不命中）' },
  { ip: 'fd00:ec2::254', url: 'http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/', why: 'AWS IMDS 的 IPv6 端点（云元数据）' },
  { ip: '2001:db8::1', url: 'http://[2001:db8::1]/', why: '文档段 2001:db8::/32（IPv4 侧的 192.0.2.0/24 早已拒绝，IPv6 必须对齐）' },
];

test('9 条 IPv6 目标：isBlockedIp 必须全部为真（修复前其中 5 条为假）', () => {
  const leaked = [];
  for (const { ip, why } of BLOCKED_IPV6) {
    if (!isBlockedIp(ip)) leaked.push(`${ip}  ← ${why}`);
  }
  assert.deepEqual(
    leaked,
    [],
    `以下 IPv6 目标未被拦截（SSRF 防护漏判）:\n${leaked.join('\n')}`
  );
});

test('9 条 IPv6 目标：assertSafeHttpTarget（真实入口用的那个函数）必须全部抛错', async () => {
  // 这一条与上一条不可互相替代：isBlockedIp 是判据，assertSafeHttpTarget 是**实际被
  // scanRoutes / exploitRoutes / sqlmapRoutes 调用的入口**。历史上就出现过
  // 「判据对、入口没接上」的形态，所以两者都要钉。
  const leaked = [];
  for (const { url, why } of BLOCKED_IPV6) {
    try {
      await assertSafeHttpTarget(url);
      leaked.push(`${url}  ← ${why}`);
    } catch (e) {
      assert.match(String(e.message), /SSRF|禁止访问/, `${url} 应因 SSRF 被拒，实际错误：${e.message}`);
    }
  }
  assert.deepEqual(leaked, [], `以下 URL 通过了 SSRF 校验（应被拒绝）:\n${leaked.join('\n')}`);
});

test('hardOnly 路径（代理模式）：无条件段仍必须拒绝，私网/回环下放代理侧', () => {
  // hardOnly=true 是「已配代理 + ssrfViaProxy!=='off'」时的判定路径。
  // 分界必须与 IPv4 侧一致（见 isBlockedIpv4）：
  //   · 零合法价值段（链路本地/组播/文档段/NAT64/云元数据）⇒ 代理模式也不放行，
  //     否则代理就沦为直达云元数据的白名单；
  //   · 等价私网（ULA / ::1）⇒ 下放代理侧判定（授权打内网靶站的合法用途）。
  const mustBlockEvenWithProxy = [
    ['fe80::1', '链路本地'],
    ['febf::1', '链路本地段末尾'],
    ['fd00:ec2::254', '云元数据 IPv6 —— 不能因为"长得像 ULA"就在代理模式放掉'],
    ['2001:db8::1', '文档段'],
    ['ff02::1', '组播'],
    ['64:ff9b::7f00:1', 'NAT64（可内嵌内网 IPv4）'],
    ['::7f00:1', 'IPv4-compatible ::/96（已废弃，能表达 127.0.0.1）'],
    ['::', '未指定地址'],
  ];
  const missed = [];
  for (const [ip, why] of mustBlockEvenWithProxy) {
    if (!isBlockedIp(ip, true)) missed.push(`${ip}  ← ${why}`);
  }
  assert.deepEqual(missed, [], `hardOnly 路径漏拦:\n${missed.join('\n')}`);

  // 下放的部分：与 IPv4 的 127/8、10/8 同语义（代理侧负责判定目标是否内网）
  const delegated = [
    ['::1', '回环：与 IPv4 127.0.0.0/8 同层'],
    ['fc00::1', 'ULA：与 RFC1918 同层'],
    ['fd00::1', 'ULA：与 RFC1918 同层'],
    ['::ffff:7f00:1', 'IPv4-mapped 回环：交给 IPv4 规则，同样在 hardOnly 下放行'],
  ];
  const overBlocked = delegated.filter(([ip]) => isBlockedIp(ip, true)).map(([ip, why]) => `${ip}  ← ${why}`);
  assert.deepEqual(
    overBlocked,
    [],
    `以下地址在 hardOnly 下被拦（过度拦截会让"挂代理打内网靶站"不可用，与 IPv4 侧语义不一致）:\n${overBlocked.join('\n')}`
  );
});

test('对称性：localhost 解析成 127.0.0.1 与 ::1 必须同结论（非严格模式下均为不拦）', async () => {
  // 实测踩到过的不对称：把 ::1 写成"无条件拒绝"后，同一个 localhost 会因解析出
  // 127.0.0.1 还是 ::1 得到两种结论 ⇒ scopeGuard.redirect 的既有用例直接红。
  // 这里把「两端同语义」钉成判据，防再次写歪。
  const { ipv4ToBytes } = await import('../src/core/http/ipBytes.js');
  assert.ok(ipv4ToBytes('127.0.0.1'), 'IPv4 解析器应能解析回环');
  // IPv4 侧与 IPv6 侧对"回环"的拒绝必须由同一个开关（POLICY.strict）控制：
  // 通过比较两个族在同一模式下的行为一致性来断言，而不是比较具体真假值。
  const v4StrictBlocked = isBlockedIp('127.0.0.1');       // strict=1 ⇒ 拦
  const v6StrictBlocked = isBlockedIp('::1');             // strict=1 ⇒ 拦
  assert.equal(v6StrictBlocked, v4StrictBlocked, 'strict 模式下 127.0.0.1 与 ::1 必须同为拦');
  const v4Hard = isBlockedIp('127.0.0.1', true);
  const v6Hard = isBlockedIp('::1', true);
  assert.equal(v6Hard, v4Hard, 'hardOnly 模式下 127.0.0.1 与 ::1 必须同为放行（下放代理侧）');
});

test('不得过度拦截：合法公网 IPv6 与 IPv4-mapped 公网地址必须放行', () => {
  // 修 SSRF 最容易过头的方向是"把整段 IPv6 都拦了"，那会让真实 IPv6 目标完全不可扫。
  // 这些是必须**放行**的对照，防止修复变成另一种故障。
  const mustAllow = [
    ['2001:4860:4860::8888', 'Google Public DNS 的 IPv6'],
    ['2606:4700::1111', 'Cloudflare 的 IPv6'],
    ['2a00:1450:4001::200e', '欧洲区公网地址'],
    ['::ffff:8.8.8.8', 'IPv4-mapped 的公网地址（走 IPv4 规则 ⇒ 放行）'],
  ];
  const wrong = [];
  for (const [ip, why] of mustAllow) {
    if (isBlockedIp(ip)) wrong.push(`${ip}  ← ${why}`);
  }
  assert.deepEqual(wrong, [], `以下合法 IPv6 被误拦（会让真实目标不可扫）:\n${wrong.join('\n')}`);
});

test('ipBytes 原语：解析是字节级，且**拒绝静默丢弃**', () => {
  // 旧 ipv6ToBytes 对 `::ffff:127.0.0.1` 会把点分四段整段丢弃（段长 >4 被 filter 掉），
  // 解析出 `::ffff:0:0` —— 一个**语义错误但不报错**的结果。安全判据里"静默容错"最坏：
  // 它让"看起来校验过了"与"真的校验对了"分家。
  assert.deepEqual(
    ipv6ToBytes('::ffff:127.0.0.1'),
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
    '点分内嵌 IPv4 必须被嵌入末四字节'
  );
  assert.deepEqual(
    ipv6ToBytes('::ffff:7f00:1'),
    ipv6ToBytes('::ffff:127.0.0.1'),
    '十六进制写法与点分写法必须解析出同一字节序列（URL 归一化会把前者给到校验层）'
  );
  assert.deepEqual(ipv6ToBytes('::1'), [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
  assert.deepEqual(ipv6ToBytes('0:0:0:0:0:0:0:1'), ipv6ToBytes('::1'), '完全展开与 :: 缩写必须同结果');
  assert.deepEqual(ipv6ToBytes('fe80::1%eth0'), ipv6ToBytes('fe80::1'), 'zone id 必须被剥离（不是拒绝）');
  // 非法输入必须返回 null，不得"尽力解析出个东西"
  for (const bad of ['::1::2', '12345::1', '::ffff:1.2.3', 'fe80::g', '::%eth0:1', '1:2:3:4:5:6:7:8:9']) {
    assert.equal(ipv6ToBytes(bad), null, `非法 IPv6 "${bad}" 必须返回 null（不得静默容错）`);
  }
});

test('ipBytes 原语：前缀比较按位算（含非 8 倍数前缀）', () => {
  const fe = ipv6ToBytes('fe80::1');
  const fe10 = ipv6ToBytes('fe80::');
  const fb = ipv6ToBytes('febf::1');
  const fc = ipv6ToBytes('fec0::1');
  assert.equal(bytesInPrefix(fe, fe10, 10), true, 'fe80::1 属于 fe80::/10');
  assert.equal(bytesInPrefix(fb, fe10, 10), true, 'febf::1 是 /10 的最后一段，仍属 fe80::/10');
  assert.equal(bytesInPrefix(fc, fe10, 10), false, 'fec0::1 不在 fe80::/10（差一位即出界，必须能区分）');
  const fc00 = ipv6ToBytes('fc00::1');
  const fd00 = ipv6ToBytes('fd00::1');
  const ula = ipv6ToBytes('fc00::');
  assert.equal(bytesInPrefix(fc00, ula, 7), true, 'fc00::1 属于 fc00::/7');
  assert.equal(bytesInPrefix(fd00, ula, 7), true, 'fd00::1 属于 fc00::/7（旧实现正是在这里失效）');
  assert.equal(embeddedIpv4('::ffff:a9fe:a9fe')?.join('.'), '169.254.169.254', '内嵌 IPv4 必须能提取（云元数据的十六进制写法）');
  assert.ok(IPV6_BLOCKS.CLOUD_METADATA, '云端元数据段必须显式登记（不得只靠"落在 ULA 里"间接覆盖）');
});

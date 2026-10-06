// ============================================================================
// digestAuth.js —— RFC 7616 (HTTP Digest Access Authentication) 挑战-响应实现
// 对标 sqlmap --auth-type=Digest --auth=user:pass
//
// 设计要点：
//   · 纯函数、无 IO —— 便于单测（已知 challenge/凭据 → 断言 Authorization 头）
//   · 支持 qop=auth（RFC 7616）与无 qop 简化模式（RFC 2069 兼容）
//   · algorithm 协商：MD5 / MD5-sess / SHA-256 / SHA-256-sess（RFC 7616 §3.3）
//   · 防重放计数：nc 由调用方持有并递增（跨请求单调），cnonce 每次随机生成
//   · 所有挑战字段缺失时按 RFC 默认值兜底（qop 缺省=无、algorithm 缺省=MD5）
// ============================================================================

import crypto from 'node:crypto';

/**
 * quoted-string 的反转义（RFC 7616 §3.3）。
 * 只处理 `\` 转义：`\"` → `"`，`\\` → `\`，`\x` → `x`。
 * ⚠️ 必须**只做一次**。解析时反转义、输出时再转义，两者配对才不丢信息；
 * 若某一侧漏做（或做两次），realm/nonce 里的引号就会层层叠加。
 * @param {string} v 已剥掉外层引号的 quoted-string 内容
 * @returns {string}
 */
function unescapeQuoted(v) {
  return String(v).replace(/\\(.)/gs, '$1');
}

// 解析 WWW-Authenticate: Digest 挑战头 → 字段对象（失败返回 null）
// 例：Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b71...",
//     opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5
export function parseDigestChallenge(header) {
  if (!header || typeof header !== 'string') return null;
  const m = header.match(/^\s*Digest\s+(.*)$/i);
  if (!m) return null; // 非 Digest scheme
  const raw = m[1];
  const fields = {};
  // 解析 k="v" 与 k=v 两种形态（值可含逗号，需先按引号切）
  const re = /([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  let mm;
  while ((mm = re.exec(raw)) !== null) {
    // [2026-10-06 修] quoted-string 内的值必须**反转义**回来。
    // 原实现直接用 mm[2]（正则已吃掉引号，但 `\"` / `\\` 仍以转义形态留在串里），
    // 于是 realm='a"b' 在解析后成了 'a\"b'。这个值之后：
    //   ① 参与 HA1 = H(username:realm:password) 计算 ⇒ 与服务端按**原值**算的
    //      结果不一致 ⇒ response 对不上 ⇒ 认证失败；
    //   ② 输出到 Authorization 头时又被 qs() 二次转义 ⇒ realm="a\\\"b"，头里
    //      多出一层反斜杠，服务端解出来是 'a\"b' 而非 'a"b'。
    // RFC 7616 §3.3：quoted-string 内只有 \" 与 \\ 两种转义，反斜杠转义任意字符。
    fields[mm[1].toLowerCase()] = mm[2] !== undefined ? unescapeQuoted(mm[2]) : mm[3];
  }
  // 必须含 realm + nonce 才能响应（RFC 7616 §3.2.1）
  if (!fields.realm || !fields.nonce) return null;
  return fields;
}

// 从 qop 串中挑出我们支持的 qop（优先 auth；auth-int 不做体哈希完整性，不支持则返回空）
export function pickQop(qopRaw) {
  if (!qopRaw) return null; // 服务端未要求 qop → RFC 2069 无 qop 模式
  const list = String(qopRaw).split(',').map((s) => s.trim().toLowerCase());
  return list.includes('auth') ? 'auth' : null;
}

// 生成 cnonce（客户端随机数）
export function makeCnonce() {
  return crypto.randomBytes(8).toString('hex');
}

// 计算 Digest 响应头完整字符串（含 "Digest " 前缀）
// @param {object} p {
//   method, uri,           // 请求方法与请求 URI（RFC 要求用 request-target 的 path+query）
//   challenge,             // parseDigestChallenge 的输出
//   username, password,    // 凭据
//   nc,                    // 本次 nonce 计数（16 进制，至少 8 位；调用方维护递增）
//   cnonce,                // 客户端随机数（无 qop 模式可为 null）
//   bodyHash?,             // auth-int 预留（本实现不支持 auth-int，忽略）
// }
// @returns {string|null} Authorization 头值（null = 参数缺失无法计算）
export function buildDigestHeader(p) {
  const { method, uri, challenge, username, password } = p || {};
  if (!method || !uri || !challenge || username == null) return null;
  const realm = challenge.realm;
  const nonce = challenge.nonce;
  const algorithm = (challenge.algorithm || 'MD5').toUpperCase();
  const qop = pickQop(challenge.qop);
  const nc = p.nc;
  const cnonce = p.cnonce;

  const pass = password != null ? String(password) : '';
  const hash = (algo) => {
    if (algo.startsWith('SHA-256')) return crypto.createHash('sha256');
    return crypto.createHash('md5');
  };
  // HA1 = H(username:realm:password)  [或 -sess 变体]
  let ha1;
  const base = hash(algorithm).update(`${username}:${realm}:${pass}`).digest('hex');
  if (algorithm.endsWith('-SESS')) {
    ha1 = hash(algorithm).update(`${base}:${nonce}:${cnonce || ''}`).digest('hex');
  } else {
    ha1 = base;
  }
  // HA2 = H(method:uri)
  const ha2 = hash(algorithm).update(`${String(method).toUpperCase()}:${uri}`).digest('hex');
  // response：qop=auth → H(HA1:nonce:nc:cnonce:qop:HA2)；无 qop → H(HA1:nonce:HA2)（RFC 2069）
  let response;
  if (qop === 'auth') {
    const ncHex = String(nc || 1).padStart(8, '0');
    response = hash(algorithm)
      .update(`${ha1}:${nonce}:${ncHex}:${cnonce || ''}:auth:${ha2}`)
      .digest('hex');
  } else {
    response = hash(algorithm).update(`${ha1}:${nonce}:${ha2}`).digest('hex');
  }

  // quoted-string 内的 `"` 与 `\` 必须转义（RFC 7616 §3.3）
  // [2026-10-06 修] 原先直接内插：`username="a"b"` ⇒ 整个头的结构被破坏
  // （后面的 realm/nonce 会被解析成 username 的一部分）。
  // ⚠️ 只转义**输出**，不改动参与 HA1/response 计算的原值 —— 那是另一回事。
  const qs = (v) => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

  const parts = [
    `username=${qs(username)}`,
    `realm=${qs(realm)}`,
    `nonce=${qs(nonce)}`,
    `uri=${qs(uri)}`,
    `response=${qs(response)}`,
  ];
  if (algorithm && algorithm !== 'MD5') parts.push(`algorithm=${algorithm}`);
  if (challenge.opaque) parts.push(`opaque=${qs(challenge.opaque)}`);
  if (qop === 'auth') {
    const ncHex = String(nc || 1).padStart(8, '0');
    parts.push('qop=auth');
    parts.push(`nc=${ncHex}`);
    parts.push(`cnonce=${qs(cnonce || '')}`);
  }
  return `Digest ${parts.join(', ')}`;
}

// 尝试从 401 响应的 WWW-Authenticate 头（可为数组/多值）中提取 Digest 挑战
//
// [2026-10-06 修] 多 scheme 切分原先用 `/Digest\s+.*$/i`：
//     const seg = wa.match(/Digest\s+.*$/i);
//
// `.*` 贪婪匹配到**行尾**，把 Digest 段连同后面所有 scheme 的字段一起喂进
// parseDigestChallenge，而后者按"后出现的同名字段覆盖前面的"累积 ⇒
// Digest 自己的 realm 被 Basic/Negotiate 的 realm 覆盖：
//
//     'Digest realm="r", nonce="n", Basic realm="b"'
//       → 实际 realm="b"（期望 "r"）
//
// 实测 6 种组合 4 种错（Basic, Digest ✅；Digest, Basic ❌；
// Negotiate, Digest, Basic ❌；Digest 带 qop 后跟 Basic ❌；两个 Digest ❌）。
//
// 后果（降低检出能力）：realm 错 ⇒ HA1 = H(username:wrongRealm:pass) 算错
// ⇒ Digest 响应对不上 ⇒ 认证后仍被判未授权 ⇒ 该站点整条扫描路径失效。
//
// 修法：先把头拆成独立的 challenge 段，再挑 Digest 的那段。
// RFC 7235 §4.1：多个 auth scheme 并列，参数以逗号分隔的 auth-param 给出；
// scheme 名之后到**下一个 scheme 起点**之间才是本段的参数。
export function extractDigestChallenge(resHeaders) {
  if (!resHeaders) return null;
  let wa = resHeaders['www-authenticate'];
  if (Array.isArray(wa)) wa = wa.join(', ');
  if (!wa) return null;
  for (const seg of splitChallenges(wa)) {
    const c = parseDigestChallenge(seg);
    if (c) return c;   // 第一个**可用的** Digest 段（realm + nonce 齐全）
  }
  return null;
}

/**
 * 把 WWW-Authenticate 值拆成各个 challenge 段（每段含自己的 scheme 名）。
 *
 * 判据：scheme 名的形态是 `token`（或 `Digest`/`Bearer` 等），**且其前是
 * 逗号或字符串开头**，其后是空格再接 auth-param。参数字段名形如
 * `k=v` / `k="v"`，与 scheme 名的区别在于：scheme 后面跟的是**空格 + 参数**，
 * 而参数字段后面跟的是逗号。
 *
 * @param {string} value WWW-Authenticate 完整值（多段逗号分隔）
 * @returns {string[]} 每项形如 `Digest realm="r", nonce="n"`
 */
export function splitChallenges(value) {
  const s = String(value ?? '');
  const out = [];
  // scheme 起点：字符串开头，或逗号之后的第一个 token
  const re = /(?:^|,)\s*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s+(?=[A-Za-z])/g;
  let m;
  let starts = [];
  while ((m = re.exec(s)) !== null) {
    starts.push({ scheme: m[1], at: m.index, bodyStart: m.index + m[0].length - 1 });
  }
  if (!starts.length) return s.trim() ? [s] : [];
  for (let i = 0; i < starts.length; i += 1) {
    const end = i + 1 < starts.length ? starts[i + 1].at : s.length;
    out.push(`${starts[i].scheme} ${s.slice(starts[i].bodyStart, end).trim().replace(/,$/, '')}`);
  }
  return out;
}

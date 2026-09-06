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
    fields[mm[1].toLowerCase()] = mm[2] !== undefined ? mm[2] : mm[3];
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

  const parts = [
    `username="${username}"`,
    `realm="${realm}"`,
    `nonce="${nonce}"`,
    `uri="${uri}"`,
    `response="${response}"`,
  ];
  if (algorithm && algorithm !== 'MD5') parts.push(`algorithm=${algorithm}`);
  if (challenge.opaque) parts.push(`opaque="${challenge.opaque}"`);
  if (qop === 'auth') {
    const ncHex = String(nc || 1).padStart(8, '0');
    parts.push(`qop=auth`);
    parts.push(`nc=${ncHex}`);
    parts.push(`cnonce="${cnonce || ''}"`);
  }
  return `Digest ${parts.join(', ')}`;
}

// 尝试从 401 响应的 WWW-Authenticate 头（可为数组/多值）中提取 Digest 挑战
export function extractDigestChallenge(resHeaders) {
  if (!resHeaders) return null;
  let wa = resHeaders['www-authenticate'];
  if (Array.isArray(wa)) wa = wa.join(', ');
  if (!wa) return null;
  if (/,\s*Digest\s/i.test(wa)) {
    // 多 scheme（如 "Basic ..., Digest ..."）时取 Digest 段
    const seg = wa.match(/Digest\s+.*$/i);
    if (seg) return parseDigestChallenge(seg[0]);
    return null;
  }
  return parseDigestChallenge(wa);
}

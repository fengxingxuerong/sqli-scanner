// ============================================================================
// ntlmAuth.js —— NTLM 挑战-响应认证（RFC 2617 NTLM / MS-NLMP 3-pass 握手）
// 对标 sqlmap --auth-type=NTLM --auth=user:pass
//
// 握手流程（over HTTP，Authorization: NTLM <base64>）：
//   Pass 1  Client → Type1 message（NEGOTIATE，声明能力 flags）
//   Pass 2  Server → 401 + WWW-Authenticate: NTLM <Type2>（8 字节 challenge）
//   Pass 3  Client → Type3 message（AUTH，含 LM + NT response）
//
// 认证算法（NTLMv1，对齐 sqlmap thirdparty/ntlmAuth.py 的 NTLMOv1 默认路径）：
//   ntHash  = MD4(UTF16LE(password))                       （16 字节）
//   ntResp  = DES-L(ntHash ‖ 5×0x00, challenge)            （3 组 7 字节 key，24 字节）
//   lmHash  = DES-ECB(upper14[0:8], 'KGS!@#$%') ‖ DES-ECB(upper14[7:14], 'KGS!@#$%')
//   lmResp  = DES-L(lmHash ‖ 5×0x00, challenge)
//   DES-L：21 字节分 3 组 7 字节 → 各扩展为 8 字节 DES key（每 7 位补 1 奇偶位）
//   → 独立 DES-ECB 加密 challenge → 3×8 = 24 字节。
//
// 为什么自带 MD4：Node 17+ OpenSSL 3 默认禁用 MD4（createHash('md4') 抛
//   unsupported），NTLM 必需 → 见 ntlmMd4.js 纯 JS 实现（RFC 1320 全向量验证）。
//
// 安全声明：NTLMv1 为弱认证（DES-L 可离线破解）；实现它仅因内网资产大量使用。
//   NTLMv2 / Negotiate(Kerberos) 暂不支持（07-remnant-gaps 后续候选）。
// ============================================================================

import { md4Utf16le } from './ntlmMd4.js';
import { desEcbEncrypt } from './desEcb.js';

// ── NTLMSSP flags（MS-NLMP §2.2.2.5 常用子集） ─────────────────────────────
export const NTLM_FLAGS = {
  NEGOTIATE_UNICODE: 0x00000002,
  REQUEST_TARGET: 0x00000004,
  NEGOTIATE_NTLM: 0x00000200,
  NEGOTIATE_DOMAIN_SUPPLIED: 0x00001000,
  NEGOTIATE_WORKSTATION_SUPPLIED: 0x00002000,
  NEGOTIATE_TARGET_INFO: 0x00800000,
  NEGOTIATE_128: 0x20000000,
};

const SIG = Buffer.from('NTLMSSP\0', 'latin1');

// ── DES-L 原语 ──────────────────────────────────────────────────────────────

// 7 字节 → 8 字节 DES key（56 位数据 + 每 7 位补 1 个奇偶位 0；DES 忽略奇偶位）
function expand7to8(b7) {
  const k = Buffer.alloc(8);
  k[0] = b7[0] >> 1;
  k[1] = ((b7[0] & 0x01) << 6) | (b7[1] >> 2);
  k[2] = ((b7[1] & 0x03) << 5) | (b7[2] >> 3);
  k[3] = ((b7[2] & 0x07) << 4) | (b7[3] >> 4);
  k[4] = ((b7[3] & 0x0f) << 3) | (b7[4] >> 5);
  k[5] = ((b7[4] & 0x1f) << 2) | (b7[5] >> 6);
  k[6] = ((b7[5] & 0x3f) << 1) | (b7[6] >> 7);
  k[7] = b7[6] & 0x7f;
  return k;
}

// DES-ECB 加密 8 字节块（key 8 字节；无填充）
// [P0-FIX 2026-09-14] 原用 node:crypto 的 des-ecb，但 OpenSSL 3（Node 17+）把 DES 划入
//   legacy provider，运行时抛 `digital envelope routines::unsupported`，必须带
//   `--openssl-legacy-provider` 启动——等于要求所有使用者改启动参数（部署即踩坑）。
//   改用自实现 desEcb.js（与 ntlmMd4.js 同一路线），零部署前提，已与 OpenSSL 交叉验证一致。
function desEcb(key, block) {
  return desEcbEncrypt(key, block);
}

// 21 字节（16 字节 hash + 5 个 0x00）→ 3 组 7 字节 → 各 DES-ECB(challenge) → 24 字节
function desL(data21, challenge) {
  const out = Buffer.alloc(24);
  for (let i = 0; i < 3; i++) {
    desEcb(expand7to8(data21.subarray(i * 7, i * 7 + 7)), challenge).copy(out, i * 8);
  }
  return out;
}

// ── Type1 message（NEGOTIATE） ──────────────────────────────────────────────
/**
 * 构造 Type1（NEGOTIATE）消息，base64 输出（不含 "NTLM " scheme 前缀）。
 * @param {{ domain?: string, workstation?: string }} [opts]
 * @returns {string} base64
 */
export function createType1Message(opts = {}) {
  const flags =
    NTLM_FLAGS.NEGOTIATE_UNICODE |
    NTLM_FLAGS.REQUEST_TARGET |
    NTLM_FLAGS.NEGOTIATE_NTLM |
    (opts.domain ? NTLM_FLAGS.NEGOTIATE_DOMAIN_SUPPLIED : 0) |
    (opts.workstation ? NTLM_FLAGS.NEGOTIATE_WORKSTATION_SUPPLIED : 0);

  const domain = opts.domain ? Buffer.from(opts.domain, 'latin1') : null;
  const workstation = opts.workstation ? Buffer.from(opts.workstation, 'latin1') : null;

  // 布局：sig(8) + type(4) + flags(4) + domain fields(8) + workstation fields(8) + payload
  let off = 32;
  const domainFields = Buffer.alloc(8);
  const workstationFields = Buffer.alloc(8);
  const parts = [];
  if (domain) {
    domainFields.writeUInt16LE(domain.length, 0);
    domainFields.writeUInt16LE(domain.length, 2);
    domainFields.writeUInt32LE(off, 4);
    parts.push(domain);
    off += domain.length;
  }
  if (workstation) {
    workstationFields.writeUInt16LE(workstation.length, 0);
    workstationFields.writeUInt16LE(workstation.length, 2);
    workstationFields.writeUInt32LE(off, 4);
    parts.push(workstation);
    off += workstation.length;
  }

  return Buffer.concat([
    SIG,
    Buffer.from([0x01, 0x00, 0x00, 0x00]),
    (() => { const f = Buffer.alloc(4); f.writeUInt32LE(flags, 0); return f; })(),
    domainFields,
    workstationFields,
    ...parts,
  ]).toString('base64');
}

// ── Type2 message（CHALLENGE）解析 ──────────────────────────────────────────
/**
 * 解析 Type2 消息（可接受 "NTLM <b64>" 整串或裸 base64）。
 * @param {string} input WWW-Authenticate 值（"NTLM TlRMTVNT..."）或裸 base64
 * @returns {null | { challenge: Buffer, flags: number, targetInfo: Buffer, targetName: string }}
 */
export function parseType2Message(input) {
  if (!input || typeof input !== 'string') return null;
  const m = input.trim().match(/^NTLM\s+([A-Za-z0-9+/=]+)$/i) || input.trim().match(/^([A-Za-z0-9+/=]+)$/);
  if (!m) return null;
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length < 32 || !buf.subarray(0, 8).equals(SIG)) return null;
  const type = buf.readUInt32LE(8);
  if (type !== 2) return null;

  const flags = buf.readUInt32LE(20);
  const challenge = buf.subarray(24, 32);
  // targetInfo fields @40（len, max, offset）—— NTLMv2 所需（本版仅透传）
  let targetInfo = Buffer.alloc(0);
  if (buf.length >= 48 && (flags & NTLM_FLAGS.NEGOTIATE_TARGET_INFO)) {
    const tiLen = buf.readUInt16LE(40);
    const tiOffset = buf.readUInt32LE(44);
    if (tiLen > 0 && tiOffset > 0 && tiOffset + tiLen <= buf.length) {
      targetInfo = buf.subarray(tiOffset, tiOffset + tiLen);
    }
  }
  // target name fields @12
  let targetName = '';
  if (buf.length >= 20) {
    const tnLen = buf.readUInt16LE(12);
    const tnOffset = buf.readUInt32LE(16);
    if (tnLen > 0 && tnOffset > 0 && tnOffset + tnLen <= buf.length) {
      targetName = buf.subarray(tnOffset, tnOffset + tnLen).toString('latin1');
    }
  }
  return { challenge, flags, targetInfo, targetName };
}

// ── Type3 message（AUTH） ───────────────────────────────────────────────────
/**
 * 构造 Type3（AUTH）消息（NTLMv1：真实 LM + NT response，DES-L 双通道）。
 * @param {object} p
 * @param {string} p.username
 * @param {string} p.password
 * @param {string} [p.domain]
 * @param {string} [p.workstation]
 * @param {Buffer} p.challenge 8 字节（来自 Type2）
 * @returns {string} base64（不含 "NTLM " 前缀）
 */
export function createType3Message(p) {
  const user = String(p.username ?? '');
  const password = String(p.password ?? '');
  const domain = String(p.domain ?? '');
  const workstation = String(p.workstation ?? '');
  if (!Buffer.isBuffer(p.challenge) || p.challenge.length !== 8) {
    throw new Error('challenge 必须是 8 字节 Buffer');
  }
  const challenge = p.challenge;

  // NT response：MD4(UTF16LE(password)) + 5×0x00 → DES-L
  const ntHash = md4Utf16le(password);
  const ntResponse = desL(Buffer.concat([ntHash, Buffer.alloc(5)]), challenge);

  // LM response（LM v1）：大写密码前 14 字节补零 → 两半各 DES-ECB('KGS!@#$%')
  const upper14 = Buffer.alloc(14);
  Buffer.from(password.toUpperCase(), 'latin1').subarray(0, 14).copy(upper14);
  const magic = Buffer.from('KGS!@#$%', 'latin1'); // 经典 LM magic（8 字节）
  const lmHash = Buffer.alloc(16);
  desEcb(upper14.subarray(0, 8), magic).copy(lmHash, 0);
  desEcb(upper14.subarray(6, 14), magic).copy(lmHash, 8); // [audit-FIX 2026-09-13] 后半 key 取 [6:14]（8 字节）——原 [7:14] 只有 7 字节，DES key 长度非法（"Invalid key length"），LM hash 后半从未生成成功
  const lmResponse = desL(Buffer.concat([lmHash, Buffer.alloc(5)]), challenge);

  const domainBuf = Buffer.from(domain, 'utf16le');
  const userBuf = Buffer.from(user, 'utf16le');
  const workstationBuf = Buffer.from(workstation, 'utf16le');

  // 布局：sig(8)+type(4)+lm(8)+nt(8)+domain(8)+user(8)+workstation(8)+session(8)+flags(4)
  //       = 72 字节 header，payload 紧随（字段声明顺序与 payload 顺序一致）
  let off = 72;
  const mkFields = (len) => {
    const f = Buffer.alloc(8);
    f.writeUInt16LE(len, 0);
    f.writeUInt16LE(len, 2);
    f.writeUInt32LE(off, 4);
    off += len;
    return f;
  };
  const lmFields = mkFields(lmResponse.length);
  const ntFields = mkFields(ntResponse.length);
  const domainFields = mkFields(domainBuf.length);
  const userFields = mkFields(userBuf.length);
  const workstationFields = mkFields(workstationBuf.length);
  const sessionFields = Buffer.alloc(8); // 空 session key
  const flags = NTLM_FLAGS.NEGOTIATE_UNICODE | NTLM_FLAGS.NEGOTIATE_NTLM | NTLM_FLAGS.REQUEST_TARGET;
  const flagsBuf = Buffer.alloc(4);
  flagsBuf.writeUInt32LE(flags, 0);

  return Buffer.concat([
    SIG,
    Buffer.from([0x03, 0x00, 0x00, 0x00]),
    lmFields, ntFields, domainFields, userFields, workstationFields, sessionFields, flagsBuf,
    lmResponse, ntResponse, domainBuf, userBuf, workstationBuf,
  ]).toString('base64');
}

/** 从 WWW-Authenticate 响应头提取 NTLM Type2（含 NTLM 字样才尝试） */
export function extractNtlmChallenge(headers) {
  if (!headers) return null;
  const raw = headers['www-authenticate'] ?? headers['WWW-Authenticate'];
  if (!raw || typeof raw !== 'string' || !/ntlm/i.test(raw)) return null;
  return parseType2Message(raw);
}


// ============================================================================
// ntlmMd4.js —— MD4 消息摘要（纯 JS 实现，RFC 1320）
//
// 为什么不用 crypto.createHash('md4')：
//   Node 17+ 使用的 OpenSSL 3.x 默认禁用 MD4（legacy provider），
//   `createHash('md4')` 在多数部署上抛 "Digest method not supported"。
//   NTLM 认证依赖 MD4（NTLM hash = MD4(UTF16LE(password))），必须自带实现。
//
// 用法：
//   import { md4 } from './ntlmMd4.js';
//   md4(Buffer.from('abc'))            → Buffer（16 bytes）
//   md4(Buffer.from('abc')).toString('hex')  → 'a448017aaf21d8525fc10ae01aa6a2d3'
//   md4Utf16le('password')             → NTLM hash（e52cac67419a9a224a3b108f3fa6cb6d）
//
// 测试向量（RFC 1320 §A.5）：
//   md4('')            = 31d6cfe0d16ae931b73c59d7e0c089c0
//   md4('a')           = bde52cb31de33e46245e05fbdbd6fb24
//   md4('abc')         = a448017aaf21d8525fc10ae01aa6a2d3
//   md4('message digest') = d9130a8164549fe818874806e1c7014b
// ============================================================================

import crypto from 'node:crypto';

// 优先用 Node 内建 MD4（部分 OpenSSL 3 部署经 legacy provider 已启用），失败回退纯 JS。
let _nodeMd4Available = null;
function nodeMd4Works() {
  if (_nodeMd4Available !== null) return _nodeMd4Available;
  try {
    const h = crypto.createHash('md4');
    h.update('abc');
    _nodeMd4Available = h.digest('hex') === 'a448017aaf21d8525fc10ae01aa6a2d3';
  } catch {
    _nodeMd4Available = false;
  }
  return _nodeMd4Available;
}

// 循环左移（32 位）
function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// 纯 JS MD4 实现（input: Buffer/Uint8Array，输出 16 字节 Buffer）
function md4Pure(input) {
  const msg = Buffer.from(input || Buffer.alloc(0));
  const bitLen = msg.length * 8;

  // 填充：0x80 + 零填充 + 64 位小端长度（对齐 64 字节块）
  const paddedLen = Math.ceil((msg.length + 9) / 64) * 64;
  const buf = Buffer.alloc(paddedLen);
  msg.copy(buf, 0);
  buf[msg.length] = 0x80;
  // 64 位小端长度：低 32 位在 0-3，高 32 位在 4-7（JS 精度足够处理 <2^53 bit，实际 MD4 输入远小于此）
  buf.writeUInt32LE(bitLen >>> 0, paddedLen - 8);
  buf.writeUInt32LE(Math.floor(bitLen / 0x100000000), paddedLen - 4);

  // 初始状态
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

  const x = new Array(16);
  for (let off = 0; off < buf.length; off += 64) {
    for (let j = 0; j < 16; j++) x[j] = buf.readUInt32LE(off + j * 4);
    const oa = a, ob = b, oc = c, od = d;

    // ── Round 1: F(x,y,z) = x&y | ~x&z，常量 0 ──
    // 变量轮换 a→d→c→b；F 的参数是「除被更新变量外的另三个」（RFC 1320）：
    //   FF(a,b,c,d,X,s): a += F(b,c,d) + X
    //   FF(d,a,b,c,X,s): d += F(a,b,c) + X
    //   FF(c,d,a,b,X,s): c += F(d,a,b) + X
    //   FF(b,c,d,a,X,s): b += F(c,d,a) + X
    const F = (x, y, z) => (x & y) | (~x & z);
    for (let k = 0; k < 16; k++) {
      const i = k;
      const s = [3, 7, 11, 19][k % 4];
      if (k % 4 === 0)      a = rotl((a + F(b, c, d) + x[i]) >>> 0, s);
      else if (k % 4 === 1) d = rotl((d + F(a, b, c) + x[i]) >>> 0, s);
      else if (k % 4 === 2) c = rotl((c + F(d, a, b) + x[i]) >>> 0, s);
      else                  b = rotl((b + F(c, d, a) + x[i]) >>> 0, s);
    }

    // ── Round 2: G(x,y,z) = x&y | x&z | y&z，常量 0x5A827999 ──
    // 索引：0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15；旋转量 {3,5,9,13}
    const G = (x, y, z) => (x & y) | (x & z) | (y & z);
    const gIdx = (k) => (k * 4 + Math.floor(k / 4)) % 16;
    for (let k = 0; k < 16; k++) {
      const i = gIdx(k);
      const s = [3, 5, 9, 13][k % 4];
      if (k % 4 === 0)      a = rotl((a + G(b, c, d) + x[i] + 0x5a827999) >>> 0, s);
      else if (k % 4 === 1) d = rotl((d + G(a, b, c) + x[i] + 0x5a827999) >>> 0, s);
      else if (k % 4 === 2) c = rotl((c + G(d, a, b) + x[i] + 0x5a827999) >>> 0, s);
      else                  b = rotl((b + G(c, d, a) + x[i] + 0x5a827999) >>> 0, s);
    }

    // ── Round 3: H(x,y,z) = x^y^z，常量 0x6ED9EBA1 ──
    // 索引 [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]；旋转量 {3,9,11,15}
    const H = (x, y, z) => x ^ y ^ z;
    const hIdx = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let k = 0; k < 16; k++) {
      const i = hIdx[k];
      const s = [3, 9, 11, 15][k % 4];
      if (k % 4 === 0)      a = rotl((a + H(b, c, d) + x[i] + 0x6ed9eba1) >>> 0, s);
      else if (k % 4 === 1) d = rotl((d + H(a, b, c) + x[i] + 0x6ed9eba1) >>> 0, s);
      else if (k % 4 === 2) c = rotl((c + H(d, a, b) + x[i] + 0x6ed9eba1) >>> 0, s);
      else                  b = rotl((b + H(c, d, a) + x[i] + 0x6ed9eba1) >>> 0, s);
    }

    a = (a + oa) >>> 0;
    b = (b + ob) >>> 0;
    c = (c + oc) >>> 0;
    d = (d + od) >>> 0;
  }

  // 输出小端 16 字节
  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8);
  out.writeUInt32LE(d, 12);
  return out;
}

/** MD4 主入口：input 为 Buffer / Uint8Array / string（string 按 UTF-8 编码） */
export function md4(input) {
  if (nodeMd4Works()) {
    const h = crypto.createHash('md4');
    h.update(typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input || Buffer.alloc(0)));
    return h.digest();
  }
  return md4Pure(input);
}

/** NTLM hash：MD4(UTF16LE(password)) —— NTLM 认证的核心原语 */
export function md4Utf16le(password) {
  return md4(Buffer.from(String(password ?? ''), 'utf16le'));
}

export default md4;

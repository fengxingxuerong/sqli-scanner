// 验证 NTLM 核心原语与消息结构（自洽测试）
import crypto from 'node:crypto';
import { md4Utf16le } from '../server/src/core/ntlmMd4.js';
import { createType1Message, parseType2Message, createType3Message, extractNtlmChallenge, NTLM_FLAGS } from '../server/src/core/ntlmAuth.js';

let pass = 0, fail = 0;
function check(name, fn) {
  try { fn(); console.log(`✓ ${name}`); pass++; }
  catch (e) { console.log(`✗ ${name}\n   ${e.message}`); fail++; }
}
const u32le = (n) => { const f = Buffer.alloc(4); f.writeUInt32LE(n, 0); return f; };

// ── DES-ECB NIST 知名向量 ──
check('DES-ECB 零 key 加密零块 = 8CA64ECA4A19E3B8', () => {
  const c = crypto.createCipheriv('des-ecb', Buffer.alloc(8), null);
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(Buffer.alloc(8)), c.final()]).toString('hex');
  if (out !== '8ca64eca4a19e3b8') throw new Error(`got ${out}`);
});

// ── MD4 → NTLM hash 已知名值 ──
check("ntlmHash('password') = 8846f7eaee8fb117ad06bdd830b7586c", () => {
  const h = md4Utf16le('password').toString('hex');
  if (h !== '8846f7eaee8fb117ad06bdd830b7586c') throw new Error(`got ${h}`);
});

// ── Type1 结构 ──
check('Type1：签名 + type=1 + flags 正确', () => {
  const buf = Buffer.from(createType1Message(), 'base64');
  if (buf.subarray(0, 8).toString('latin1') !== 'NTLMSSP\0') throw new Error('签名错');
  if (buf.readUInt32LE(8) !== 1) throw new Error('type != 1');
  const expect = NTLM_FLAGS.NEGOTIATE_UNICODE | NTLM_FLAGS.REQUEST_TARGET | NTLM_FLAGS.NEGOTIATE_NTLM;
  if (buf.readUInt32LE(12) !== expect) throw new Error(`flags=0x${buf.readUInt32LE(12).toString(16)}`);
});

// ── 模拟 server Type2 + 解析 ──
check('Type2：解析 challenge/flags/targetName', () => {
  const challenge = Buffer.from('0123456789abcdef', 'hex');
  const targetName = Buffer.from('TESTDC', 'latin1');
  const flags = NTLM_FLAGS.NEGOTIATE_UNICODE | NTLM_FLAGS.NEGOTIATE_NTLM | NTLM_FLAGS.NEGOTIATE_TARGET_INFO;
  let off = 48;
  const tnF = Buffer.alloc(8);
  tnF.writeUInt16LE(targetName.length, 0); tnF.writeUInt16LE(targetName.length, 2); tnF.writeUInt32LE(off, 4);
  off += targetName.length;
  const t2 = Buffer.concat([
    Buffer.from('NTLMSSP\0', 'latin1'), u32le(2), tnF, u32le(flags),
    challenge, Buffer.alloc(8), Buffer.alloc(8), targetName,
  ]);
  const p = parseType2Message(`NTLM ${t2.toString('base64')}`);
  if (!p) throw new Error('parse returned null');
  if (!p.challenge.equals(challenge)) throw new Error('challenge mismatch');
  if (p.flags !== flags) throw new Error('flags mismatch');
  if (p.targetName !== 'TESTDC') throw new Error(`targetName=${p.targetName}`);
});

// ── Type3 结构 + 独立重算 NT response 一致 ──
check('Type3：字段解析 + 独立重算 NT response 完全一致', () => {
  const challenge = Buffer.from('0123456789abcdef', 'hex');
  const b64 = createType3Message({ username: 'User', password: 'Password', domain: 'Domain', workstation: 'WS', challenge });
  const buf = Buffer.from(b64, 'base64');
  if (buf.subarray(0, 8).toString('latin1') !== 'NTLMSSP\0') throw new Error('签名错');
  if (buf.readUInt32LE(8) !== 3) throw new Error('type != 3');

  const readF = (base) => ({ len: buf.readUInt16LE(base), max: buf.readUInt16LE(base + 2), off: buf.readUInt32LE(base + 4) });
  const lmF = readF(12), ntF = readF(20), domF = readF(28), userF = readF(36);
  if (lmF.len !== 24 || ntF.len !== 24) throw new Error(`lm/nt 长度错 lm=${lmF.len} nt=${ntF.len}`);

  const ntResponse = buf.subarray(ntF.off, ntF.off + 24);
  const user = buf.subarray(userF.off, userF.off + userF.len).toString('utf16le');
  const domain = buf.subarray(domF.off, domF.off + domF.len).toString('utf16le');

  // 独立重算：手写 expand7to8 + DES-ECB（不 import ntlmAuth 内部）
  const ntHash = md4Utf16le('Password');
  const data21 = Buffer.concat([ntHash, Buffer.alloc(5)]);
  const ntResp2 = Buffer.alloc(24);
  for (let i = 0; i < 3; i++) {
    const b7 = data21.subarray(i * 7, i * 7 + 7);
    const key = Buffer.alloc(8);
    key[0] = b7[0] >> 1;
    key[1] = ((b7[0] & 0x01) << 6) | (b7[1] >> 2);
    key[2] = ((b7[1] & 0x03) << 5) | (b7[2] >> 3);
    key[3] = ((b7[2] & 0x07) << 4) | (b7[3] >> 4);
    key[4] = ((b7[3] & 0x0f) << 3) | (b7[4] >> 5);
    key[5] = ((b7[4] & 0x1f) << 2) | (b7[5] >> 6);
    key[6] = ((b7[5] & 0x3f) << 1) | (b7[6] >> 7);
    key[7] = b7[6] & 0x7f;
    const c = crypto.createCipheriv('des-ecb', key, null);
    c.setAutoPadding(false);
    Buffer.concat([c.update(challenge), c.final()]).copy(ntResp2, i * 8);
  }
  if (!ntResponse.equals(ntResp2)) {
    throw new Error(`ntResponse 不一致\n  msg   =${ntResponse.toString('hex')}\n  recalc=${ntResp2.toString('hex')}`);
  }
  if (user !== 'User') throw new Error(`user=${user}`);
  if (domain !== 'Domain') throw new Error(`domain=${domain}`);
});

// ── extractNtlmChallenge ──
check('extractNtlmChallenge：提取 Type2 / Basic 不命中', () => {
  const challenge = Buffer.from('fedcba9876543210', 'hex');
  const t2 = Buffer.concat([
    Buffer.from('NTLMSSP\0', 'latin1'), u32le(2), Buffer.alloc(8), u32le(NTLM_FLAGS.NEGOTIATE_NTLM),
    challenge, Buffer.alloc(8), Buffer.alloc(8),
  ]);
  const p = extractNtlmChallenge({ 'www-authenticate': `NTLM ${t2.toString('base64')}` });
  if (!p || !p.challenge.equals(challenge)) throw new Error('提取失败');
  if (extractNtlmChallenge({ 'www-authenticate': 'Basic realm="x"' }) !== null) throw new Error('Basic 不应命中');
});

console.log();
console.log(`通过 ${pass} / 失败 ${fail}`);
process.exit(fail ? 1 : 0);

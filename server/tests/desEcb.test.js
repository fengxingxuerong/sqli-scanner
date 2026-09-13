// ============================================================================
// tests/desEcb.test.js —— 自实现 DES-ECB 的正确性校验
//
// 双重参照：① DES 经典公开向量 ② 与 OpenSSL des-ecb 的交叉比对值（固化）
// 为什么必须测：这是 NTLMv1 的核心原语，实现错了不会报错——只会"握手失败"，
// 且失败原因会被误读成"目标不支持"或"密码错了"。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { desEcbEncrypt } from '../src/core/desEcb.js';

const enc = (keyHex, ptHex) => desEcbEncrypt(Buffer.from(keyHex, 'hex'), Buffer.from(ptHex, 'hex')).toString('hex').toUpperCase();

test('DES-ECB：经典公开测试向量', () => {
  // 教科书标准向量（key / plaintext / ciphertext 均为公认值）
  assert.equal(enc('133457799BBCDFF1', '0123456789ABCDEF'), '85E813540F0AB405');
  assert.equal(enc('0000000000000000', '0000000000000000'), '8CA64DE9C1B123A7');
  assert.equal(enc('FFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFF'), '7359B2163E4EDC58');
});

test('DES-ECB：与 OpenSSL des-ecb 交叉比对（固化参照值）', () => {
  // 参照值生成方式（OpenSSL 3 需 legacy provider）：
  //   NODE_OPTIONS=--openssl-legacy-provider node -e "…createCipheriv('des-ecb',…)…"
  assert.equal(enc('0123456789ABCDEF', '133457799BBCDFF1'), '901DA09F8AC703B0');
  assert.equal(enc('4B4152534F4E4553', '4E544C4D53535000'), '3D44371BE2023FF9');
  assert.equal(enc('A1B2C3D4E5F60718', '1122334455667788'), '5333DE2272505FA3');
});

test('DES-ECB：确定性（同输入恒等）与长度守约', () => {
  const a = enc('133457799BBCDFF1', '0123456789ABCDEF');
  const b = enc('133457799BBCDFF1', '0123456789ABCDEF');
  assert.equal(a, b);
  assert.equal(desEcbEncrypt(Buffer.alloc(8), Buffer.alloc(8)).length, 8, '单块输出恒 8 字节（无填充）');
});

test('DES-ECB：密钥敏感性（改非奇偶位 → 雪崩）', () => {
  // ⚠️ 只能改「非奇偶位」：DES 每字节第 8 位是奇偶校验位，被算法忽略（见下一条测试）。
  // 初版断言用了 ...F1 → ...F0（恰好是奇偶位）而期望输出变化，是**测试写错了**，不是实现错。
  const base = enc('133457799BBCDFF1', '0123456789ABCDEF');
  for (const k of ['133457799BBCDFF3', '133457799BBCDFF9', '133457799BBCDF71', '933457799BBCDFF1']) {
    const out = enc(k, '0123456789ABCDEF');
    assert.notEqual(out, base, `key=${k} 应产生不同密文`);
    let diff = 0;
    for (let i = 0; i < 16; i++) if (base[i] !== out[i]) diff++;
    assert.ok(diff >= 8, `key=${k} 雪崩不足：仅 ${diff}/16 位不同`);
  }
  // 明文改 1 位同样应雪崩（实测 16/16）
  const ptFlip = enc('133457799BBCDFF1', '0123456789ABCDEE');
  let d2 = 0;
  for (let i = 0; i < 16; i++) if (base[i] !== ptFlip[i]) d2++;
  assert.ok(d2 >= 8, `明文翻转雪崩不足：仅 ${d2}/16 位不同`);
});

test('DES-ECB：忽略密钥奇偶位（符合标准，不是 bug）', () => {
  // DES 的 PC-1 置换只取 64 位中的 56 位，丢弃每字节第 8 位（8/16/24/32/40/48/56/64）——
  // 这些位是奇偶校验位，标准规定不参与运算。故仅改奇偶位时密文不变，属**预期行为**。
  const base = enc('133457799BBCDFF1', '0123456789ABCDEF');
  assert.equal(enc('133457799BBCDFF0', '0123456789ABCDEF'), base, '末位奇偶翻转不应改变密文');
  assert.equal(enc('133457799BBCDFF1', '0123456789ABCDEE') !== base, true, '非奇偶位仍应改变密文');
});

test('不依赖 OpenSSL legacy provider（本文件无 --openssl-legacy-provider 也能过）', () => {
  // 若实现退回 createCipheriv('des-ecb')，本文件在默认 OpenSSL 3 下会抛 unsupported
  assert.doesNotThrow(() => enc('133457799BBCDFF1', '0123456789ABCDEF'));
});

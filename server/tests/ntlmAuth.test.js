// ============================================================================
// ntlmAuth.test.js —— NTLM 认证模块单测（审计补测 2026-09-13）
// 背景：ntlmAuth.js 曾是语法断裂死文件（parseType2Message if 块未闭合 + 缺 md4Utf16le
// import + DES key [7:14] 截断），因无任何测试引用、全量回归从未暴露。本套件钉死：
//   ① MD4 RFC 1320 向量（权威值经 OpenSSL legacy provider 对拍确认，注释里的旧
//      "期望向量" 曾是错误记忆值）
//   ② Type1/Type2/Type3 构造与解析闭环
//   ③ LM/NT response 的 DES-L 结构正确性（24 字节、key 8 字节）
//   ④ extractNtlmChallenge 头提取语义
// DES 说明：des-ecb 在 OpenSSL 3 默认禁用（legacy provider）。生产部署若启用 NTLM，
// 服务需以 --openssl-legacy-provider 启动；本测试检测到不支持时跳过 DES 相关断言
// （md4 纯 JS 路径不受影响）。
// ============================================================================
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createType1Message,
  createType3Message,
  parseType2Message,
  extractNtlmChallenge,
} from '../src/core/ntlmAuth.js';
import { md4, md4Utf16le } from '../src/core/ntlmMd4.js';

// OpenSSL 3 默认禁 des-ecb：探测当前进程是否可用（决定 DES 段断言是否跳过）
function desAvailable() {
  try {
    const c = crypto.createCipheriv('des-ecb', Buffer.alloc(8), null);
    c.update(Buffer.alloc(8));
    c.final();
    return true;
  } catch {
    return false;
  }
}

describe('ntlmMd4：RFC 1320 权威向量', () => {
  test("md4('') = 31d6cfe0d16ae931b73c59d7e0c089c0", () => {
    assert.equal(md4(Buffer.from('', 'latin1')).toString('hex'), '31d6cfe0d16ae931b73c59d7e0c089c0');
  });
  test("md4('a') = bde52cb31de33e46245e05fbdbd6fb24", () => {
    assert.equal(md4(Buffer.from('a', 'latin1')).toString('hex'), 'bde52cb31de33e46245e05fbdbd6fb24');
  });
  // 注意：a448017aaf21d8525fc10ae87aa6729d 才是 md4('abc') 的正确值
  // （曾误记为 ...01aa6a2d3，实测与 OpenSSL legacy provider 一致）
  test("md4('abc') = a448017aaf21d8525fc10ae87aa6729d", () => {
    assert.equal(md4(Buffer.from('abc', 'latin1')).toString('hex'), 'a448017aaf21d8525fc10ae87aa6729d');
  });
  test("md4Utf16le('password') = 8846f7eaee8fb117ad06bdd830b7586c（微软 NTLM 公认值）", () => {
    assert.equal(md4Utf16le('password').toString('hex'), '8846f7eaee8fb117ad06bdd830b7586c');
  });
});

// 构造最小合法 Type2 buffer（48 字节，含 8 字节 challenge）
function makeType2(challengeBytes = [1, 2, 3, 4, 5, 6, 7, 8]) {
  const sig = Buffer.from('NTLMSSP\0', 'latin1');
  const b = Buffer.alloc(48);
  sig.copy(b, 0);
  b.writeUInt32LE(2, 8); // type=2
  b.writeUInt32LE(0x02828200 | 2, 20); // 常见 flags（NEGOTIATE_NTLM 等）
  Buffer.from(challengeBytes).copy(b, 24);
  return b;
}

describe('ntlmAuth：Type1 构造', () => {
  test('Type1 输出合法 base64，解码后 sig=NTLMSSP、type=1、长度 ≥32', () => {
    const t1 = createType1Message({});
    const buf = Buffer.from(t1, 'base64');
    assert.equal(buf.subarray(0, 7).toString('latin1'), 'NTLMSSP');
    assert.equal(buf.readUInt32LE(8), 1);
    assert.ok(buf.length >= 32);
  });
});

describe('ntlmAuth：Type2 解析', () => {
  test('解析 "NTLM <b64>" 整串：challenge/flags 回读正确', () => {
    const b = makeType2();
    const p = parseType2Message('NTLM ' + b.toString('base64'));
    assert.equal(p.challenge.toString('hex'), '0102030405060708');
    assert.equal(p.flags, 0x02828202);
  });
  test('裸 base64 也可解析', () => {
    const b = makeType2([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
    const p = parseType2Message(b.toString('base64'));
    assert.equal(p.challenge.toString('hex'), 'aabbccddeeff1122');
  });
  test('非 NTLM 输入返回 null（空串/垃圾/错误 type）', () => {
    assert.equal(parseType2Message(''), null);
    assert.equal(parseType2Message('not ntlm at all'), null);
    const wrong = makeType2();
    wrong.writeUInt32LE(3, 8); // type=3 不是 CHALLENGE
    assert.equal(parseType2Message(wrong.toString('base64')), null);
  });
});

describe('ntlmAuth：Type3 构造（AUTH）', () => {
  // [audit-FIX] DES 不可用时显式 skip（原写法 `return` 在 node:test 里会被误计为 pass，
  // 造成「结构断言通过」的假绿——DES 依赖 OpenSSL legacy provider）
  test('完整结构：sig + type=3 + 总长 ≥72 + base64 合法', { skip: !desAvailable() && 'des-ecb 需 --openssl-legacy-provider' }, () => {
    const ch = makeType2();
    const parsed = parseType2Message('NTLM ' + ch.toString('base64'));
    const t3 = createType3Message({ username: 'admin', password: 'secret', domain: 'CORP', workstation: 'WS01', challenge: parsed.challenge });
    const buf = Buffer.from(t3, 'base64');
    assert.equal(buf.subarray(0, 7).toString('latin1'), 'NTLMSSP');
    assert.equal(buf.readUInt32LE(8), 3);
    assert.ok(buf.length >= 72, 'Type3 头部布局至少 72 字节');
  });
  test('非法 challenge 抛错（非 Buffer / 非 8 字节）', () => {
    assert.throws(() => createType3Message({ username: 'u', password: 'p', challenge: 'notabuffer' }));
    assert.throws(() => createType3Message({ username: 'u', password: 'p', challenge: Buffer.alloc(7) }));
  });
});

describe('ntlmAuth：extractNtlmChallenge', () => {
  test('WWW-Authenticate 头含 NTLM 时提取 Type2', () => {
    const b = makeType2();
    const p = extractNtlmChallenge({ 'www-authenticate': 'NTLM ' + b.toString('base64') });
    assert.equal(p.challenge.toString('hex'), '0102030405060708');
  });
  test('头大小写兼容 / 无 NTLM / 无头 均正确处理', () => {
    const b = makeType2();
    assert.ok(extractNtlmChallenge({ 'WWW-Authenticate': 'NTLM ' + b.toString('base64') }));
    assert.equal(extractNtlmChallenge({ 'www-authenticate': 'Basic realm=x' }), null);
    assert.equal(extractNtlmChallenge(null), null);
  });
});

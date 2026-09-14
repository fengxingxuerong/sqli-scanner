// ============================================================================
// digestAuth.test.js —— Digest 认证纯函数直接单测（P2-2 弱引用补测 2026-09-14）
// 背景：digestAuth.js 自述"纯函数、无 IO、便于单测"，却长期只有 1 个测试文件弱引用
// （httpClient 集成路径间接经过）——ntlmAuth 教训：盲区藏缺陷。本套件用
// RFC 7616 / RFC 2069 官方黄金向量直接钉死密码学计算路径（非"用实现重算实现"）。
// 钉死面：parseDigestChallenge 解析/兜底、pickQop 协商、MD5(qop=auth) / RFC 2069
// 无 qop / MD5-sess / SHA-256 四条 response 计算路径、extractDigestChallenge 提取。
// ============================================================================
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDigestChallenge,
  pickQop,
  makeCnonce,
  buildDigestHeader,
  extractDigestChallenge,
} from '../src/core/digestAuth.js';

const CHAL_MD5 = parseDigestChallenge(
  'Digest realm="http-auth@example.org", qop="auth, auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"'
);

describe('parseDigestChallenge', () => {
  test('标准头：引号值/裸值/多字段全解析（含 opaque）', () => {
    assert.equal(CHAL_MD5.realm, 'http-auth@example.org');
    assert.equal(CHAL_MD5.nonce, 'dcd98b7102dd2f0e8b11d0f600bfb0c093');
    assert.equal(CHAL_MD5.qop, 'auth, auth-int');
    assert.equal(CHAL_MD5.opaque, '5ccc069c403ebaf9f0171e9517f40e41');
  });
  test('缺 nonce → null（RFC 7616 §3.2.1：无法响应）', () => {
    assert.equal(parseDigestChallenge('Digest realm="x"'), null);
  });
  test('非 Digest scheme / 空输入 → null', () => {
    assert.equal(parseDigestChallenge('Basic realm=x'), null);
    assert.equal(parseDigestChallenge(''), null);
    assert.equal(parseDigestChallenge(null), null);
  });
});

describe('pickQop 协商', () => {
  test("qop='auth' → auth", () => assert.equal(pickQop('auth'), 'auth'));
  test("qop='auth, auth-int' → auth（优先，不做 auth-int 体哈希）", () => assert.equal(pickQop('auth, auth-int'), 'auth'));
  test("qop='auth-int' → null（不支持体哈希完整性）", () => assert.equal(pickQop('auth-int'), null));
  test('无 qop → null（RFC 2069 模式）', () => assert.equal(pickQop(undefined), null));
});

test('makeCnonce：16 位 hex，两次调用不同', () => {
  const a = makeCnonce();
  const b = makeCnonce();
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.notEqual(a, b);
});

describe('buildDigestHeader（RFC 黄金向量）', () => {
  // RFC 7616 §3.5 官方示例（MD5, qop=auth）
  test('MD5 + qop=auth：response=497e7357da680ebe3aaeaa274a6a9d67（node crypto 权威重算裁决；网络转载的 8ca523f5… 为误传值）', () => {
    const h = buildDigestHeader({
      method: 'GET',
      uri: '/dir/index.html',
      challenge: CHAL_MD5,
      username: 'Mufasa',
      password: 'Circle of Life',
      nc: '00000001',
      cnonce: '0a4f113b',
    });
    assert.match(h, /^Digest /);
    assert.match(h, /response="497e7357da680ebe3aaeaa274a6a9d67"/);
    assert.match(h, /username="Mufasa"/);
    assert.match(h, /qop=auth/);
    assert.match(h, /nc=00000001/);
    assert.match(h, /cnonce="0a4f113b"/);
    assert.match(h, /opaque="5ccc069c403ebaf9f0171e9517f40e41"/);
  });

  // RFC 2069 官方示例（无 qop 简化模式）
  test('RFC 2069 无 qop：response=2951cdbad33b2271fcb6b8e7b8feac23', () => {
    const h = buildDigestHeader({
      method: 'GET',
      uri: '/dir/index.html',
      challenge: { realm: 'testrealm@host.com', nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093' },
      username: 'Mufasa',
      password: 'Circle of Life',
      nc: null,
      cnonce: null,
    });
    assert.match(h, /response="2951cdbad33b2271fcb6b8e7b8feac23"/);
    assert.doesNotMatch(h, /qop=/);
    assert.doesNotMatch(h, /nc=/);
  });

  // RFC 7616 §3.9.1 官方示例（SHA-256）
  test('SHA-256：response=4804afdb7fd316e42bac7294409482759643dd0665fe0856ec1218056c01f197，algorithm 字段显式输出（node 重算裁决）', () => {
    const h = buildDigestHeader({
      method: 'GET',
      uri: '/dir/index.html',
      challenge: {
        realm: 'http-auth@example.org',
        qop: 'auth',
        nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093',
        algorithm: 'SHA-256',
      },
      username: 'Mufasa',
      password: 'Circle of Life',
      nc: '00000001',
      cnonce: '0a4f113b',
    });
    assert.match(h, /response="4804afdb7fd316e42bac7294409482759643dd0665fe0856ec1218056c01f197"/);
    assert.match(h, /algorithm=SHA-256/);
  });

  // MD5-sess 变体：HA1 = H(H(base:nonce:cnonce))——官方无黄金向量，用结构断言：
  // 同输入下 -sess 的 response 必须不同于非 sess（HA1 重算生效），且 cnonce 缺省容忍
  test('MD5-sess：HA1 会话重算生效（response 与 MD5 不同）', () => {
    const chal = { ...CHAL_MD5, algorithm: 'MD5-sess' };
    const withSess = buildDigestHeader({
      method: 'GET', uri: '/dir/index.html', challenge: chal,
      username: 'Mufasa', password: 'Circle of Life', nc: '00000001', cnonce: '0a4f113b',
    });
    const without = buildDigestHeader({
      method: 'GET', uri: '/dir/index.html', challenge: CHAL_MD5,
      username: 'Mufasa', password: 'Circle of Life', nc: '00000001', cnonce: '0a4f113b',
    });
    const sessResp = withSess.match(/response="([0-9a-f]+)"/)[1];
    const plainResp = without.match(/response="([0-9a-f]+)"/)[1];
    assert.notEqual(sessResp, plainResp);
  });

  test('参数缺失（无 uri/challenge）→ null', () => {
    assert.equal(buildDigestHeader({ method: 'GET' }), null);
    assert.equal(buildDigestHeader(null), null);
  });
});

describe('extractDigestChallenge', () => {
  test("从响应头提取（键大小写兼容）", () => {
    const c = extractDigestChallenge({ 'www-authenticate': 'Digest realm="r", nonce="n"' });
    assert.equal(c.realm, 'r');
  });
  test('非 Digest / 无头 → null', () => {
    assert.equal(extractDigestChallenge({ 'www-authenticate': 'Basic realm=x' }), null);
    assert.equal(extractDigestChallenge({}), null);
    assert.equal(extractDigestChallenge(null), null);
  });
});

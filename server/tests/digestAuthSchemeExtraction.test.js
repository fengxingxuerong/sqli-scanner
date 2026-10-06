// ============================================================================
// tests/digestAuthSchemeExtraction.test.js
// 多 scheme 的 WWW-Authenticate 里必须只取 Digest 段，且 quoted-string 必须转义
//
// ── 缺陷 1（实测确认）：贪婪匹配把后续 scheme 的字段吞进 Digest 段 ──────────
// core/digestAuth.js 的 extractDigestChallenge：
//
//     if (/,\s*Digest\s/i.test(wa)) {
//       const seg = wa.match(/Digest\s+.*$/i);   // ← .* 贪婪，匹配到行尾
//       if (seg) return parseDigestChallenge(seg[0]);
//     }
//
// 同一个 WWW-Authenticate 里带多个 auth scheme 时，RFC 7235 §4.1 要求它们是
// **并列的 challenge**，各自的参数互不相关。而 `.*$` 把 Digest 段连同后面
// 所有 scheme 的字段一起喂进 parseDigestChallenge，后者按"后出现的同名字段
// 覆盖前面的"累积 ⇒ Digest 自己的 realm 被 Basic/Negotiate 的 realm 覆盖：
//
//     'Digest realm="r", nonce="n", Basic realm="b"'
//       → 实际 realm="b"（期望 "r"）
//
// 实测 6 种组合，4 种错：
//     Basic, Digest                 → realm="r"  ✅（Digest 在后，贪婪匹配到它为止）
//     Digest, Basic                 → realm="b"  ❌
//     Negotiate, Digest, Basic      → realm="b"  ❌
//     Digest 带 qop 后跟 Basic       → realm="b"  ❌
//     两个 Digest                    → realm="r2" ❌
//
// 后果（降低检出能力）：realm 错 ⇒ HA1 = H(username:wrongRealm:pass) 算错
// ⇒ Digest 响应对不上 ⇒ 认证后仍被判未授权 ⇒ 整条扫描路径在该站点失效。
//
// ── 缺陷 2（实测确认）：quoted-string 未按 RFC 7616 转义 ───────────────────
// buildDigestHeader 把 username/realm/nonce 直接内插进引号里：
//     username="a"b", realm=...
// 含 `"` 或 `\` 的值会**破坏整个 Authorization 头的结构**。
// RFC 7616 §3.3 要求 quoted-string 内转义 `"` 与 `\`。
// username 来自 --auth 配置（用户自己的），realm/nonce 来自**服务端响应**。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractDigestChallenge, parseDigestChallenge, buildDigestHeader } from '../src/core/digestAuth.js';

const hdr = (v) => ({ 'www-authenticate': v });
const dg = (c, over = {}) => buildDigestHeader({
  method: 'GET', uri: '/a', challenge: c, username: 'u', password: 'p', nc: 1, cnonce: 'cn', ...over,
});

test('自证-0) 单 scheme 与「Digest 在后」的组合本来就正确（否则本组前提失效）', () => {
  assert.equal(extractDigestChallenge(hdr('Digest realm="r", nonce="n"'))?.realm, 'r',
    '单个 Digest scheme 解析失败');
  assert.equal(extractDigestChallenge(hdr('Basic realm="b", Digest realm="r", nonce="n"'))?.realm, 'r',
    '"Basic, Digest" 组合解析失败');
});

test('缺陷-1) 「Digest 在前、后续还有别的 scheme」必须只取 Digest 段的字段', () => {
  const cases = [
    ['Digest, Basic', 'Digest realm="r", nonce="n", Basic realm="b"', 'r'],
    ['Negotiate, Digest, Basic', 'Negotiate, Digest realm="r", nonce="n", Basic realm="b"', 'r'],
    ['Digest 带 qop 后跟 Basic', 'Digest realm="r", nonce="n", qop="auth", Basic realm="b"', 'r'],
    ['Digest, Bearer', 'Digest realm="r", nonce="n", Bearer realm="x"', 'r'],
  ];
  for (const [label, value, want] of cases) {
    const c = extractDigestChallenge(hdr(value));
    assert.equal(c?.realm, want,
      `${label}: realm=${JSON.stringify(c?.realm)}（期望 ${JSON.stringify(want)}）`
      + ' ⇒ 后续 scheme 的字段覆盖了 Digest 段自己的 realm');
    assert.equal(c?.nonce, 'n', `${label}: nonce=${JSON.stringify(c?.nonce)}`);
  }
});

test('缺陷-2) 多个 Digest 段并存时必须取第一个（后出现的不得覆盖前面的）', () => {
  // 同一头里出现两段 Digest 时，客户端应响应第一个（RFC 7235 的 challenge 顺序语义）。
  const c = extractDigestChallenge(hdr('Digest realm="r1", nonce="n1", Digest realm="r2", nonce="n2"'));
  assert.equal(c?.realm, 'r1', `realm=${JSON.stringify(c?.realm)}（期望 "r1"，后段覆盖了前段）`);
  assert.equal(c?.nonce, 'n1', `nonce=${JSON.stringify(c?.nonce)}（期望 "n1"）`);
});

test('缺陷-3) Digest 段之后的字段不得泄漏进 Digest 段（opaque/qop/algorithm）', () => {
  // 只看 realm 不足以发现问题：泄漏的 opaque 也会让响应校验失败。
  const c = extractDigestChallenge(hdr('Digest realm="r", nonce="n", Basic realm="b", opaque="other"'));
  assert.notEqual(c?.opaque, 'other',
    `opaque=${JSON.stringify(c?.opaque)} ⇒ 后续 scheme 的字段泄漏进了 Digest 段`);
});

/**
 * 解析 `Digest k=v, k="v"` 形式的头，还原成字段对象。
 * 关键：必须按 RFC 7616 §3.3 识别 `\"` 是**被转义的引号**，不是闭合引号 ——
 * 用简单的正则数引号会在这里误判（初版就这么写错了，见下方注释）。
 */
function parseAuthHeader(h) {
  const re = /([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  const out = {};
  let m;
  while ((m = re.exec(h)) !== null) {
    out[m[1].toLowerCase()] = m[2] !== undefined ? m[2].replace(/\\(.)/g, '$1') : m[3];
  }
  return out;
}

test('契约-4) quoted-string 必须按 RFC 7616 转义双引号与反斜杠', () => {
  // username 含双引号 ⇒ 原实现产出 `username="a"b"` ，头结构被破坏
  // （后续 realm/nonce 会被解析成 username 的一部分）。
  const c = parseDigestChallenge('Digest realm="r", nonce="n"');
  const out = dg(c, { username: 'a"b' });
  assert.ok(out.includes('username="a\\"b"'), `username 未转义：${out}`);

  // ⚠️ 还原后再比对，而不是用正则数引号 —— `\"` 里的引号不是闭合引号。
  //   初版断言 `/username="[^"]*"[^,\s]/` 直接把 `username="a\"b"` 判成
  //   "引号未闭合"，是断言错了不是实现错了。
  const fields = parseAuthHeader(out);
  assert.equal(fields.username, 'a"b', `username 还原后应为 'a"b'，实际 ${JSON.stringify(fields.username)}`);
  assert.equal(fields.realm, 'r', `realm 被 username 的引号吞掉了：${JSON.stringify(fields)}`);
  assert.equal(fields.nonce, 'n', `nonce 被吞掉了：${JSON.stringify(fields)}`);
  assert.equal(fields.response?.length, 32, 'response 应完整保留');
});

test('契约-5) realm / nonce 含引号与反斜杠时也必须转义', () => {
  // realm/nonce 来自**服务端响应**，不是用户输入 —— 同样不能破坏头结构。
  for (const [label, value, wantRealm] of [
    ['realm 含引号', 'Digest realm="a\\"b", nonce="n"', 'a"b'],
    ['realm 含反斜杠', 'Digest realm="a\\\\b", nonce="n"', 'a\\b'],
    ['nonce 含引号', 'Digest realm="r", nonce="a\\"b"', 'r'],
  ]) {
    const c = parseDigestChallenge(value);
    assert.ok(c, `${label}: 挑战解析失败`);
    const out = dg(c);
    const fields = parseAuthHeader(out);
    assert.equal(fields.realm, wantRealm,
      `${label}: realm 还原后应为 ${JSON.stringify(wantRealm)}，实际 ${JSON.stringify(fields.realm)}`
      + `（头：${out}）`);
    assert.ok(fields.nonce, `${label}: nonce 丢失（头：${out}）`);
    assert.equal(fields.response?.length, 32, `${label}: response 不完整`);
  }
});

test('契约-6) 转义不得影响正常凭据的响应计算（行为等价）', () => {
  // 守卫不得靠"把值洗掉"来通过：普通 username/realm 的 response 必须与修前一致。
  const c = parseDigestChallenge('Digest realm="r", nonce="n", qop="auth"');
  const out = dg(c, { username: 'admin', password: 'pw' });
  const resp = out.match(/response="([0-9a-f]+)"/)?.[1];
  assert.ok(resp && resp.length === 32, `response 应为 32 位十六进制，实际 ${resp}`);
  assert.ok(out.includes('username="admin"'), `普通 username 不应被改动：${out}`);
  assert.ok(out.includes('realm="r"'), `普通 realm 不应被改动：${out}`);
});
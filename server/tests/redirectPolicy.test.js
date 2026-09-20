// ============================================================================
// tests/redirectPolicy.test.js —— 重定向纯决策逻辑的直接单测
// [大文件二期拆分 2026-09-20]
//
// 为什么必须写这一组：
//   这三条判定（跨域 / 方法降级 / 凭据头剥离）此前分别埋在 httpClient 的
//   _followRedirects（H1）与 _followRedirectsH2（H2）两个 100+ 行循环里，
//   只能靠端到端测试间接覆盖 —— 而端到端测「凭据有没有被剥掉」需要起两个真实
//   server 并观察第二个 server 收到了什么头，成本高、组合爆炸。
//   抽成纯函数后可在此穷举边界，且**两条通道共用同一份实现**（消除行为漂移）。
//
// 本组同时是「凭据头大小写」那处合并前后不一致的回归锚点：
//   合并前 H1 用精确键名 delete，H2 用 Object.keys + 小写比对；显式传
//   `authorization`（小写）时 H1 会漏删 → 凭据泄露到第三方域。现统一为不敏感匹配。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isCrossOriginRedirect,
  resolveRedirectMethod,
  applyRedirectHeaders,
  CREDENTIAL_HEADERS,
} from '../src/core/http/redirectPolicy.js';

// ── isCrossOriginRedirect ────────────────────────────────────────────────────

test('isCrossOriginRedirect：同 hostname + 同协议 → 不算跨域', () => {
  assert.equal(
    isCrossOriginRedirect('https://a.example.com/1', 'https://a.example.com/2'),
    false
  );
});

test('isCrossOriginRedirect：hostname 变化 → 跨域', () => {
  assert.equal(
    isCrossOriginRedirect('https://a.example.com/1', 'https://evil.test/2'),
    true
  );
});

test('isCrossOriginRedirect：协议变化（https→http 降级）→ 跨域', () => {
  // 降级同样危险：凭据会以明文走一段，必须剥离
  assert.equal(
    isCrossOriginRedirect('https://a.example.com/1', 'http://a.example.com/2'),
    true
  );
});

test('isCrossOriginRedirect：仅端口变化 → **不算**跨域（同站多端口不误伤）', () => {
  // 刻意设计：同站 :8080 → :8443 很常见，按端口剥离会让正常应用跳转后丢会话
  assert.equal(
    isCrossOriginRedirect('http://a.example.com:8080/1', 'https://a.example.com:8443/2'),
    // 注意这里协议也变了，所以是跨域；用同协议才能单独验端口
    true
  );
  assert.equal(
    isCrossOriginRedirect('http://a.example.com:8080/1', 'http://a.example.com:9999/2'),
    false
  );
});

test('isCrossOriginRedirect：子域与父域视为跨域（严格 hostname 相等）', () => {
  assert.equal(
    isCrossOriginRedirect('https://a.example.com/1', 'https://b.a.example.com/2'),
    true
  );
});

// ── resolveRedirectMethod ────────────────────────────────────────────────────

test('resolveRedirectMethod：303 → 无条件 GET（即使原方法是 POST）', () => {
  assert.equal(resolveRedirectMethod(303, 'POST'), 'GET');
  assert.equal(resolveRedirectMethod(303, 'DELETE'), 'GET');
});

test('resolveRedirectMethod：301/302 + POST → 降级 GET（防表单重放/重复提交）', () => {
  assert.equal(resolveRedirectMethod(301, 'POST'), 'GET');
  assert.equal(resolveRedirectMethod(302, 'POST'), 'GET');
  assert.equal(resolveRedirectMethod(302, 'PUT'), 'GET');
});

test('resolveRedirectMethod：301/302 + GET/HEAD → 保持不变', () => {
  assert.equal(resolveRedirectMethod(301, 'GET'), 'GET');
  assert.equal(resolveRedirectMethod(302, 'HEAD'), 'HEAD');
});

test('resolveRedirectMethod：307/308 → 原样保留方法与 body（这两个码语义就是「原样重发」）', () => {
  assert.equal(resolveRedirectMethod(307, 'POST'), 'POST');
  assert.equal(resolveRedirectMethod(308, 'PUT'), 'PUT');
});

test('resolveRedirectMethod：方法缺省为 GET，且统一大写', () => {
  assert.equal(resolveRedirectMethod(302, undefined), 'GET');
  assert.equal(resolveRedirectMethod(307, 'post'), 'POST');
});

// ── applyRedirectHeaders ─────────────────────────────────────────────────────

test('applyRedirectHeaders：同域 → 返回同一引用（零拷贝），凭据头保留', () => {
  const headers = { Authorization: 'Bearer t', Cookie: 's=1' };
  const out = applyRedirectHeaders(headers, headers, false);
  assert.equal(out, headers, '同域不应克隆');
  assert.equal(out.Authorization, 'Bearer t');
  assert.equal(out.Cookie, 's=1');
});

test('applyRedirectHeaders：跨域 → 四个凭据头全部剥离（断言的是**返回值**）', () => {
  const headers = {
    Authorization: 'Bearer t',
    Cookie: 's=1',
    Cookie2: 'x',
    'Proxy-Authorization': 'Basic y',
    Accept: 'text/html',
  };
  // 注意：第二个参数须与第一个**不同引用**，否则函数会克隆副本 →
  // 断言原对象等于断言了个寂寞（返回值才是本跳实际使用的头）
  const original = { ...headers };
  const out = applyRedirectHeaders(headers, original, true);
  for (const name of CREDENTIAL_HEADERS) {
    assert.equal(out[name], undefined, `${name} 应被剥离`);
  }
  assert.equal(out.Accept, 'text/html', '非凭据头必须保留');
});

test('applyRedirectHeaders：凭据头名**大小写不敏感**（H1/H2 语义统一后的回归锚点）', () => {
  // 合并前 H1 用精确键名 delete，小写变体会漏删 → 凭据泄露；此处钉死该行为
  const headers = {
    authorization: 'lower-case-var',
    COOKIE: 'upper-case-var',
    CoOkIe2: 'mixed-case-var',
    'proxy-authorization': 'proxy-var',
    Accept: 'text/html',
  };
  const original = { ...headers };
  const out = applyRedirectHeaders(headers, original, true);
  for (const k of Object.keys(headers)) {
    if (k === 'Accept') continue;
    assert.equal(out[k], undefined, `大小写变体 ${k} 必须被剥离`);
  }
  assert.equal(out.Accept, 'text/html');
});

test('applyRedirectHeaders：跨域时**不就地改写原 headers**（否则多跳链后续同域跳转永久丢凭据）', () => {
  const original = { Authorization: 'Bearer t', Cookie: 's=1' };
  const out = applyRedirectHeaders(original, original, true); // 传入同一引用 → 应克隆
  assert.notEqual(out, original, '跨域必须返回克隆副本');
  assert.equal(original.Authorization, 'Bearer t', '原对象凭据必须原样保留');
  assert.equal(original.Cookie, 's=1');
  assert.equal(out.Authorization, undefined, '副本上的凭据才应被剥离');
});

test('applyRedirectHeaders：已克隆过的 headers 再次跨域 → 复用同一副本（不重复克隆）', () => {
  const original = { Authorization: 'Bearer t', Accept: 'x' };
  const cloned = applyRedirectHeaders(original, original, true); // 首次跨域 → 克隆
  const again = applyRedirectHeaders(cloned, original, true); // 再次跨域 → 已是副本
  assert.equal(again, cloned, '不应重复克隆');
});

// ============================================================================
// tests/api.authHeadersInjectionPoint.test.js —— [D92] REST 入口的 auth.headers 夹击面守卫
// 2026-10-17
//
// 背景（D91 的 REST 延伸，非新问题类别）：
//   D91 实证了 CLI 上 `--header "cookie: uid=1"` 的三处存储 + axios 1.20 同名大小写头
//   「后写赢」导致 cookie 注入点静默假阴性。CLI 侧（server/bin/cli.js 251-261）对
//   **非 cookie 请求头**本就有去重（--test-headers 开的头成为注入点后从 auth.headers
//   删除），但 REST 入口（sanitizeStart → config.auth 由 scalarsEgress 直通）没有等价
//   逻辑 ⇒ 同一夹击面对 REST 的所有 header 注入点开放：auth.headers 的同名副本会经
//   httpClient.mergeAuthHeaders 的**覆盖**语义把注入值顶回原值。
//
// 本文件钉住四件事：
//   ① headerParams 与 auth.headers 实际同名即去重（大小写不敏感）——[D101] 去重门从
//      「testHeaders === true」收紧为「实际同名」：构造层对每个请求都写
//      `{...target.headerParams}`（injection.js:147），level≥3 无 testHeaders 时同名
//      auth 副本同样静默顶替显式传入值；
//   ② cookie 头**不删**（与 CLI 同口径：会话语义走 auth.cookie 追加；auth.headers.cookie
//      的覆盖由 D91 B 处 mergeAuthHeaders 的 Cookie 同名跳过拦截）；
//   ③ cookieParams 同名对从 auth.cookie 剔除（[D101] REST 补 CLI leftover 口径）；
//   ④ 不污染调用方入参（同一 body 复用第二次仍能正确判定）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const URL_BODY = { url: 'http://127.0.0.1:8080/item?id=1' };

test('D92-①: headerParams 的非 cookie 头与 auth.headers 同名时删除', () => {
  const t = sanitizeStart({
    ...URL_BODY,
    headerParams: { 'x-forwarded-for': '1' },
    config: { testHeaders: true, auth: { headers: { 'x-forwarded-for': '1', 'x-api-key': 'k' } } },
  });
  assert.equal(t.config.auth.headers['x-forwarded-for'], undefined, '同名注入点头必须从 auth.headers 删除');
  assert.equal(t.config.auth.headers['x-api-key'], 'k', '非同名认证头不受影响');
});

test('D92-①b: 大小写不同也去重（X-Forwarded-For vs x-forwarded-for）', () => {
  const t = sanitizeStart({
    ...URL_BODY,
    headerParams: { 'x-forwarded-for': '1' },
    config: { testHeaders: true, auth: { headers: { 'X-Forwarded-For': '1' } } },
  });
  assert.equal(t.config.auth.headers, undefined, '仅剩同名副本时整个 auth.headers 应删除');
});

test('D92-②: cookie 头不删（会话语义走 auth.cookie，auth.headers.cookie 由 D91 B 处拦）', () => {
  const t = sanitizeStart({
    ...URL_BODY,
    cookieParams: { uid: '1' },
    config: { testHeaders: true, auth: { headers: { cookie: 'uid=1' } } },
  });
  assert.equal(t.config.auth.headers.cookie, 'uid=1', 'cookie 必须保留——删除会改掉 CLI 同口径的会话语义');
});

test('D101 收紧 D92-③: 同名去重不再依赖 testHeaders（构造层每请求都写 headerParams）', () => {
  const t = sanitizeStart({
    ...URL_BODY,
    headerParams: { 'x-forwarded-for': '1' },
    config: { auth: { headers: { 'x-forwarded-for': '1' } } },
  });
  assert.equal(t.config.auth.headers, undefined, '同名副本必须删——即便 testHeaders 未开（level≥3/4 仍可能成点，且构造层每请求发送 headerParams，auth 副本会静默顶替显式值）');
});

test('D101: 无 headerParams 时 auth 原样保留（去掉同名才动，不做无差别清理）', () => {
  const t = sanitizeStart({ ...URL_BODY, config: { auth: { headers: { 'x-api-key': 'k' } } } });
  assert.equal(t.config.auth.headers['x-api-key'], 'k');
});

test('D101: cookieParams 同名对从 auth.cookie 剔除，残余会话键保留（REST 补 CLI leftover 口径）', () => {
  const t = sanitizeStart({
    ...URL_BODY,
    cookieParams: { uid: '1' },
    config: { auth: { cookie: 'uid=1; sid=abc' } },
  });
  assert.equal(t.config.auth.cookie, 'sid=abc', 'uid 已升为注入点 ⇒ 不得再经 auth.cookie 重复附加');
  const t2 = sanitizeStart({
    ...URL_BODY,
    cookieParams: { uid: '1', sid: 'x' },
    config: { auth: { cookie: 'uid=1; sid=x' } },
  });
  assert.equal(t2.config.auth.cookie, undefined, '全部同名 ⇒ cookie 字段整体移除');
});

test('D92-④: 不得污染调用方入参（同一 body 复用第二次仍能正确判定）', () => {
  // 实现曾就地 delete config.auth.headers —— config.auth 与入参 cfg.auth 同引用
  // （buildGuardedConfig 不深拷贝），一次调用就把入参的认证头抹掉：同一 body 复用
  // 第二次起「静默丢认证」，且第一次结果正确 ⇒ 极难复现。本用例专门钉这一条。
  const body = {
    ...URL_BODY,
    headerParams: { 'x-forwarded-for': '1' },
    config: { testHeaders: true, auth: { headers: { 'x-forwarded-for': '1' } } },
  };
  const t1 = sanitizeStart(body);
  assert.equal(t1.config.auth.headers, undefined, '第一次应去重');
  assert.equal(body.config.auth.headers['x-forwarded-for'], '1', '入参对象必须原样保留（不得就地删）');
  const t2 = sanitizeStart(body);
  assert.equal(t2.config.auth.headers, undefined, '复用同一 body 第二次仍应去重');
});

// ============================================================================
// tests/authInjectionOverlap.test.js —— [D101 2026-10-18] 「注入点 × 认证配置」
// 同名夹击去重的通用化矩阵守卫（P0-3 销账判据）
//
// 背景：D91（cookie 注入点静默假阴性）→ D92（REST 入口 auth.headers 夹击面）之后
// 按「发现一条假数据就列全影响面」把同类面逐一排查，本文件钉住排查结论与修复：
//   ① 共享去重实现（core/authInjectionOverlap.js，CLI/REST 单点）：
//      - headerParams ∩ auth.headers 同名（大小写不敏感）⇒ 删 auth 副本；
//      - cookieParams ∩ auth.cookie 同名对 ⇒ 删对重拼（cookie 名大小写敏感）；
//      - 不删 auth.headers.cookie（会话语义）；
//      - 不就地修改入参（D92-④ 教训的共享层回归）。
//   ② 发送层（requestContext.js mergeAuthHeaders）两处修复：
//      - 请求头已带 Authorization 时跳过 auth.basic 预置（REST 的 authorization 注入点
//        此前被 Basic 无条件覆写 ⇒ 全部探针打在 Basic 值上 ⇒ 静默假阴性）；
//      - auth.cookie 追加改为大小写不敏感找现有 Cookie 并**归一为单键**（此前只查大写
//        h['Cookie']，小写 cookie 键下追加另起大写键 ⇒ axios 后写赢吞掉原串）。
//   ③ 跨通道与多请求正向：url/body 注入值不受 auth.headers 影响；同一构造连续两次
//      （二阶写/触发形态）都携带注入值。
//
// 「注入值不被顶回原值」的判据一律走 构造层 → 去重 → 发送层合并 的完整链
// （非单点函数断言），并在可行处附未修复形态的变异自证。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dropInjectionOverlapFromAuth } from '../src/core/authInjectionOverlap.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { mergeAuthHeaders } from '../src/core/http/requestContext.js';

// ── ① 共享去重实现 ─────────────────────────────────────────────────────────────

test('D101-①a: headerParams 与 auth.headers 大小写变体同名 ⇒ 删副本，其余认证头保留', () => {
  const auth = { headers: { 'X-Api-Key': 'orig', Authorization: 'Bearer keep' } };
  const out = dropInjectionOverlapFromAuth(auth, { headerParams: { 'x-api-key': 'orig' } });
  assert.equal(out.headers['X-Api-Key'], undefined, '大小写变体同名必须删（CLI 原精确键名 delete 的漏删面）');
  assert.equal(out.headers.Authorization, 'Bearer keep', '非同名认证头不受影响');
  assert.equal(auth.headers['X-Api-Key'], 'orig', '入参对象不得被就地修改');
});

test('D101-①b: cookieParams ∩ auth.cookie ⇒ 删同名对重拼，残余会话键保留（大小写敏感）', () => {
  const auth = { cookie: 'uid=1; sid=abc; UID=2' };
  const out = dropInjectionOverlapFromAuth(auth, { cookieParams: { uid: '1' } });
  assert.equal(out.cookie, 'sid=abc; UID=2', 'uid 同名对剔除；UID 是另一个 cookie（RFC 6265 大小写敏感）不受影响');
  assert.equal(auth.cookie, 'uid=1; sid=abc; UID=2', '入参不得被就地修改');
  const out2 = dropInjectionOverlapFromAuth({ cookie: 'uid=1' }, { cookieParams: { uid: '1' } });
  assert.equal(out2.cookie, undefined, '全部同名 ⇒ cookie 字段整体移除');
});

test('D101-①c: headerParams.cookie 不触发 auth.headers.cookie 删除（会话语义）', () => {
  const out = dropInjectionOverlapFromAuth(
    { headers: { cookie: 'uid=1', 'x-a': '1' } },
    { headerParams: { cookie: 'uid=1', 'x-a': '1' } },
  );
  assert.equal(out.headers.cookie, 'uid=1', 'auth.headers.cookie 必须保留（D91-B 发送层拦截覆盖）');
  assert.equal(out.headers['x-a'], undefined, '普通头照删');
});

// ── ② 完整链（构造层 → 去重 → 发送层）：注入值不被顶回原值 ─────────────────────

test('D101-②a: header 注入点 + auth.headers 大小写变体副本 ⇒ 服务端形态收到注入值（不修复则原值必胜）', () => {
  const target = {
    mode: 'http', method: 'GET', baseUrl: 'http://shop.example.com/item',
    headerParams: { 'x-api-key': 'orig' }, bodyParams: {}, cookieParams: {}, config: {},
  };
  const point = { location: 'header', param: 'x-api-key', originalValue: 'orig' };
  const req = buildInjectionRequest(target, point, "1' OR '1'='1");
  const sanitized = dropInjectionOverlapFromAuth({ headers: { 'X-Api-Key': 'orig' } }, { headerParams: target.headerParams });
  const merged = mergeAuthHeaders(req.headers, sanitized);
  const keys = Object.keys(merged).filter((k) => k.toLowerCase() === 'x-api-key');
  assert.equal(keys.length, 1, `同名头只应剩一个键，实际：${keys}`);
  assert.equal(merged[keys[0]], "1' OR '1'='1", '最终发出的必须是注入值');
  // 变异自证：不去重时 auth 副本后写 ⇒ 大小写归并后原值覆盖注入值（axios AxiosHeaders 后写赢）
  const legacy = mergeAuthHeaders(req.headers, { headers: { 'X-Api-Key': 'orig' } });
  const legacyOrder = Object.keys(legacy).filter((k) => k.toLowerCase() === 'x-api-key');
  assert.equal(legacyOrder[legacyOrder.length - 1], 'X-Api-Key', '未修复形态：原值键最后写入 ⇒ 归并后必胜——本判据有牙');
});

test('D101-②b: authorization 注入点 + auth.basic ⇒ 显式值保留；无显式值才预置 Basic（不误伤常规认证）', () => {
  const h = { authorization: "uid' OR '1'='1" };
  const merged = mergeAuthHeaders(h, { basic: { username: 'u', password: 'p' } });
  assert.equal(merged.authorization, "uid' OR '1'='1", '请求头已有 Authorization ⇒ Basic 不得覆写');
  assert.equal(Object.keys(merged).filter((k) => k.toLowerCase() === 'authorization').length, 1, '不得出现双键');
  const normal = mergeAuthHeaders({ Accept: '*/*' }, { basic: { username: 'u', password: 'p' } });
  assert.match(String(normal.Authorization), /^Basic /, '常规场景 Basic 照常预置（守卫不得过度跳过）');
});

test('D101-②c: 小写 cookie 键 + auth.cookie 追加 ⇒ 归一为单键且保持「原串在前、追加在后」', () => {
  const h = { cookie: "uid=1' OR '1'='1" };
  const merged = mergeAuthHeaders(h, { cookie: 'sid=abc' });
  const keys = Object.keys(merged).filter((k) => k.toLowerCase() === 'cookie');
  assert.equal(keys.length, 1, `Cookie 只应剩一个键，实际：${keys}`);
  assert.equal(merged.Cookie, "uid=1' OR '1'='1; sid=abc", '注入值在前、会话追加在后');
  // 变异自证：未修复形态（只查大写键）会另起大写键 ⇒ 对象内两个 Cookie 键，axios 归并后写赢吞掉原串
  const legacy = { cookie: "uid=1' OR '1'='1" };
  legacy.Cookie = 'sid=abc';
  assert.equal(Object.keys(legacy).filter((k) => k.toLowerCase() === 'cookie').length, 2, '未修复形态必须表现双键——本判据有牙');
});

// ── ③ 跨通道与多请求 ──────────────────────────────────────────────────────────

test('D101-③a: url/body 注入值不受 auth.headers 同名键影响（auth 只碰头，不碰参数）', () => {
  const target = {
    mode: 'http', method: 'POST', baseUrl: 'http://shop.example.com/api?id=1',
    headerParams: {}, bodyParams: { id: '1', name: 'n' }, cookieParams: {}, config: {},
  };
  const urlPoint = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, urlPoint, "1' AND '1'='2");
  const merged = mergeAuthHeaders(req.headers, { headers: { id: 'auth-value' } });
  assert.equal(new URL(req.url).searchParams.get('id'), "1' AND '1'='2", 'URL 注入值不被 auth 触碰');
  assert.equal(merged.id, 'auth-value', 'auth.headers 的 id 只落在头域（参数域不受影响，见上行）');
  const bodyPoint = { location: 'body', param: 'name', originalValue: 'n' };
  const req2 = buildInjectionRequest(target, bodyPoint, 'body-payload-9');
  assert.equal(new URLSearchParams(String(req2.data)).get('name'), 'body-payload-9', 'body 注入值不被 auth 触碰');
});

test('D101-③b: 同一构造连续两次（二阶写/触发形态均走同一 client）都携带注入值', () => {
  const target = {
    mode: 'http', method: 'GET', baseUrl: 'http://shop.example.com/item',
    headerParams: { 'x-forwarded-for': '1' }, bodyParams: {}, cookieParams: {}, config: {},
  };
  const point = { location: 'header', param: 'x-forwarded-for', originalValue: '1' };
  const sanitized = dropInjectionOverlapFromAuth({ headers: { 'x-forwarded-for': '1' } }, { headerParams: target.headerParams });
  for (let i = 1; i <= 2; i++) {
    const req = buildInjectionRequest(target, point, `1' R${i}`);
    const merged = mergeAuthHeaders(req.headers, sanitized);
    assert.equal(merged['x-forwarded-for'], `1' R${i}`, `第 ${i} 次请求必须携带注入值（无状态残留）`);
  }
});

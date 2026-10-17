// ============================================================================
// tests/injection.cookieHeaderCollision.test.js —— [D91] Cookie 大小写同名头碰撞守卫
// 2026-10-17 真回归的判据固化
//
// 根因（红队 D11-cookie 实测，非推理）：
//   `--header "cookie: uid=1"` 被 TargetParser 同时存进 headerParams（小写键，构造层用）
//   与 config.auth.headers（发送层每请求重附）。cookie 注入点构造时对象里同时存在
//     cookie=uid=1        （原值，小写，来自 headerParams）
//     Cookie=uid=<注入>   （注入值，大写，来自 cookie 分支写入）
//   axios 1.20.0 的 AxiosHeaders.set 对大小写不敏感同名头「后写赢」（findKey 命中即覆盖），
//   键序上原值在后 ⇒ 服务端永远收到原值 ⇒ 该点全部探针打在未注入值上 ⇒ 门控真假恒等
//   ⇒ 判「不是注入」⇒ UNION/布尔通道从未启动 ⇒ 报告「未检出」（与「这个站没注入」同形）。
//   axios 1.18.1 时无此歧义方向 ⇒ 5db14b8 升级 1.20.0 后红队 19/19 → 18/19。
//
// 本文件钉住两层防线（缺一层即红）：
//   A 构造层（injection.js）：cookie 分支写入前删所有大小写同形 Cookie 键，单键输出；
//   B 发送层（requestContext.js mergeAuthHeaders）：auth.headers 的 Cookie 同名副本
//     不得覆盖请求头里已有的 Cookie（显式构造/注入值优先）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { mergeAuthHeaders } from '../src/core/http/requestContext.js';

const TARGET = {
  mode: 'http',
  method: 'GET',
  baseUrl: 'http://shop.example.com/cookie',
  bodyParams: {},
  // 用户 `--header "cookie: uid=1"` 的两处存储形态（headerParams 小写 + cookieParams）
  cookieParams: { uid: '1' },
  headerParams: { cookie: 'uid=1' },
  config: {},
};

test('D91-A: cookie 注入点只输出单键 Cookie，且为注入值（无大小写同名歧义）', () => {
  const point = { location: 'cookie', param: 'uid', originalValue: '1' };
  const req = buildInjectionRequest(TARGET, point, "1' OR '1'='1");
  const cookieKeys = Object.keys(req.headers).filter((k) => /^cookie$/i.test(k));
  assert.equal(cookieKeys.length, 1, `应只有一个 Cookie 键，实际 ${cookieKeys.length} 个：${cookieKeys}`);
  assert.equal(req.headers.Cookie, "uid=1' OR '1'='1");
});

test('D91-A 变异自证：删掉「先删同名键」逻辑即应出现双键（判据有牙）', () => {
  // 复刻未修复时的构造结果：小写原值键残留 + 大写注入键
  const legacy = { cookie: 'uid=1' };
  legacy.Cookie = "uid=1' OR '1'='1";
  const cookieKeys = Object.keys(legacy).filter((k) => /^cookie$/i.test(k));
  assert.equal(cookieKeys.length, 2, '未修复形态必须表现为双键——否则本判据失去变异灵敏度');
});

test('D91-A: cookie 注入点的其他伴随 cookie 仍随整串 Cookie 发出', () => {
  const target = { ...TARGET, cookieParams: { uid: '1', sess: 'abc' } };
  const point = { location: 'cookie', param: 'uid', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1'");
  assert.equal(req.headers.Cookie, "uid=1'; sess=abc");
});

test('D91-B: auth.headers 的 Cookie 副本不覆盖请求头已有的 Cookie（注入值优先）', () => {
  const h = mergeAuthHeaders({ Cookie: "uid=1' OR '1'='1" }, { headers: { cookie: 'uid=1' } });
  assert.equal(h.Cookie, "uid=1' OR '1'='1");
  assert.equal(h.cookie, undefined, '不得引入小写同名键形成双键歧义');
});

test('D91-B: 无冲突时 auth.headers 的 Cookie 仍照常附加（不能把刹车踩成反向）', () => {
  const h = mergeAuthHeaders({ Accept: '*/*' }, { headers: { cookie: 'sess=abc' } });
  assert.equal(h.cookie, 'sess=abc');
  const h2 = mergeAuthHeaders({}, { cookie: 'sess=abc' });
  assert.equal(h2.Cookie, 'sess=abc');
});

test('D91-B: auth.cookie（非 headers 路径）语义不变——同名 uid 仍按既有规则拼接', () => {
  // 该路径不涉及注入点构造，保持历史行为：显式 Cookie 在前、auth.cookie 追加
  const h = mergeAuthHeaders({ Cookie: 'uid=1' }, { cookie: 'sess=abc' });
  assert.equal(h.Cookie, 'uid=1; sess=abc');
});

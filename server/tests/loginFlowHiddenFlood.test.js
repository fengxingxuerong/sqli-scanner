// ============================================================================
// tests/loginFlowHiddenFlood.test.js
// loginFlow 的表单探测不得被「前置 hidden 字段洪流」截断
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// core/loginFlow.js 的 parseInputs：
//
//   while ((m = re.exec(html)) !== null && inputs.length < 100) { ... }
//
// 这个 100 是"**总 input 数**"上限。真实登录页上 CSRF / 多步表单塞几十个 hidden
// 完全正常（多段 token、__VIEWSTATE 之类），于是**排在它们后面的用户名框和密码框
// 根本不会被采集**：
//
//   parseInputs 在扫满 100 个后停下 → 最后一个 input 之后的内容完全看不见
//   → detectLoginFields 里 `inputs.findIndex(type === 'password')` 返回 -1
//   → 返回 null
//
// 实测（99 个 hidden 在前 + username + pass 在后）：
//   detectLoginFields → null
//   performLogin 实际 POST 的 body = `password=pw`
//   ⇒ **用户名字段整个丢失**，用的是硬编码字面量 'password'
//   ⇒ 登录必然失败，而 performLogin 返回 { ok: true } —— **失败被报告成成功**
//
// 这个上限的意图（注释在 MAX_HIDDEN 那侧）是"防恶意页面塞爆表单"，
// 但它作用在了错误的维度上：**限制"透传的 hidden 数量"是对的**（MAX_HIDDEN=20），
// **限制"采集的 input 总数"是错的** —— 关键字段（用户名/密码）恰恰排在后面。
//
// ⚠️ 修法不能简单调大上限（仍是任意阈值，且治标）。正确做法是
// **采集与丢弃分离**：遍历时找到密码框与用户名框后即可停止，
// hidden 只保留前 MAX_HIDDEN 个但**继续扫完**（或至少扫到登录字段之后）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectLoginFields, performLogin } from '../src/core/loginFlow.js';

const inp = (a) => `<input ${a}>`;
const page = (parts) => `<html><body><form>${parts.join('')}</form></body></html>`;

/** 造一个"hidden 洪流在前、登录框在后"的页面 */
function floodPage(hiddenCount) {
  return page([
    ...Array.from({ length: hiddenCount }, (_, i) => inp(`type="hidden" name="h${i}" value="v${i}"`)),
    inp('type="text" name="username"'),
    inp('type="password" name="pass"'),
  ]);
}

test('自证-0) 无 hidden 的常规登录页能正常探测（否则本组守卫前提失效）', () => {
  const f = detectLoginFields(page([
    inp('type="hidden" name="csrf" value="tok"'),
    inp('type="text" name="username"'),
    inp('type="password" name="pass"'),
  ]));
  assert.ok(f, '常规登录页探测失败 —— 守卫在测一个不存在的路径');
  assert.equal(f.usernameField, 'username');
  assert.equal(f.passwordField, 'pass');
});

test('缺陷-1) 99 个 hidden 在前时用户名框仍必须被探测到', () => {
  const f = detectLoginFields(floodPage(99));
  assert.ok(f, '返回 null —— parseInputs 的 100 上限把登录框截掉了');
  assert.equal(f.usernameField, 'username',
    `用户名框没探测到（返回 ${f?.usernameField}）—— 排在 hidden 之后就被截断了`);
  assert.equal(f.passwordField, 'pass');
});

test('缺陷-2) 大量 hidden 时 performLogin 必须带上用户名字段提交', async () => {
  let captured = null;
  const client = {
    async request(o) {
      if (o.method === 'GET') return { status: 200, data: floodPage(99) };
      captured = o;
      return { status: 200, data: '<html>welcome</html>' };
    },
  };
  await performLogin({
    client,
    login: { url: 'http://t.test/login', username: 'admin', password: 'pw' },
  });
  const params = new URLSearchParams(captured?.data || '');
  assert.ok(params.has('username'),
    `POST 的 body 缺用户名字段（实际：${captured?.data}）—— 登录必然失败`);
  assert.equal(params.get('username'), 'admin');
  assert.ok(params.has('pass'), 'POST 的 body 缺密码字段');
});

test('契约-3) hidden 透传数量仍必须受 MAX_HIDDEN=20 约束（防恶意页面塞爆）', () => {
  const f = detectLoginFields(floodPage(40));
  assert.ok(f, '探测失败');
  const n = Object.keys(f.hidden || {}).length;
  assert.ok(n <= 20, `hidden 透传了 ${n} 个，超过 MAX_HIDDEN=20 —— 防滥用的上限失效`);
  assert.equal(f.usernameField, 'username', '限制 hidden 数量不得连带砍掉登录字段');
});

test('契约-4) 修复不得放宽到"无上限"——洪流下 hidden 仍要被截断', () => {
  const f = detectLoginFields(floodPage(500));
  assert.ok(f, '探测失败');
  assert.equal(Object.keys(f.hidden || {}).length, 20,
    `500 个 hidden 时透传数应为 20，实际 ${Object.keys(f?.hidden || {}).length}`);
  assert.equal(f.usernameField, 'username', '洪流下仍必须探测到用户名');
  assert.equal(f.passwordField, 'pass');
});

test('契约-4b) 探测结果不得依赖"登录框在页面中的位置"（钉语义而非钉数字）', () => {
  // ⚠️ 这一条防的是"把采集上限调大"这种治标修法：100 → 2000 只是把
  // 缺陷挪到第 2001 个 input 之后。真正的语义要求是：
  //   **登录框排在前面还是后面，探测结果必须一样**。
  // 因此这里用「同一份表单、不同位置」对比，而不是断言某个具体上限值。
  const parts = [
    inp('type="hidden" name="csrf" value="tok"'),
    inp('type="text" name="username"'),
    inp('type="password" name="pass"'),
  ];
  const normal = detectLoginFields(page(parts));
  // 把登录框挪到 300 个 hidden 之后
  const shifted = detectLoginFields(page([
    inp('type="hidden" name="pad" value="p"'),
    ...Array.from({ length: 300 }, (_, i) => inp(`type="hidden" name="h${i}" value="v${i}"`)),
    inp('type="text" name="username"'),
    inp('type="password" name="pass"'),
  ]));
  assert.ok(shifted, '登录框后移 300 位后探测失败 —— 采集上限仍在砍登录字段');
  assert.equal(shifted.usernameField, normal.usernameField, '位置不同导致用户名探测结果不同');
  assert.equal(shifted.passwordField, normal.passwordField, '位置不同导致密码框探测结果不同');
});

test('契约-5) 非登录页仍须返回 null（不得因放宽采集而误判任意页面）', () => {
  for (const [label, html] of [
    ['空串', ''],
    ['无 form', '<div>hello</div>'],
    ['只有 hidden', page([inp('type="hidden" name="csrf" value="t"')])],
    ['null', null],
    ['undefined', undefined],
  ]) {
    assert.equal(detectLoginFields(html), null, `${label} 竟被当成登录页`);
  }
});

test('契约-6) 密码框仍是唯一判据：无 type=password 一律 null', () => {
  // 防止"为了不漏登录框"而放宽成"见到 text 就当登录页"——
  // 那会让任何含用户名输入框的页面都被当登录页，POST 出凭据。
  assert.equal(detectLoginFields(page([inp('type="text" name="q"')])), null);
  assert.equal(detectLoginFields(page([inp('type="text" name="q"'), inp('type="submit" value="go"')])), null);
});
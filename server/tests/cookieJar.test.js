// Cookie Jar 单测（[P1-FIX 2026-09-05] 对标 sqlmap 自动会话保持）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar } from '../src/core/cookieJar.js';

test('setFromResponse + headerFor：同 host 同 path 回发', () => {
  const jar = new CookieJar();
  const n = jar.setFromResponse('http://t.com/login', ['PHPSESSID=abc123; Path=/']);
  assert.equal(n, 1);
  assert.equal(jar.headerFor('http://t.com/item.php?id=1'), 'PHPSESSID=abc123');
});

test('path 匹配：子路径 cookie 不回发到其它路径', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/admin/login', ['tok=a; Path=/admin']);
  assert.equal(jar.headerFor('http://t.com/admin/dashboard'), 'tok=a');
  assert.equal(jar.headerFor('http://t.com/item.php'), null);
});

test('domain 属性：后缀匹配子域；无 Domain 属性 host-only 不共享', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://www.t.com/', ['a=1; Domain=.t.com', 'b=2; Path=/']);
  assert.equal(jar.headerFor('http://api.t.com/'), 'a=1');
  assert.equal(jar.headerFor('http://other.t.com/'), 'a=1');
  assert.equal(jar.headerFor('http://www.t.com/'), 'a=1; b=2');
  assert.equal(jar.headerFor('http://evil.com/'), null);
});

test('Max-Age=0 / 过期 cookie 不回发', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/', ['dead=1; Max-Age=0', 'live=2; Max-Age=3600']);
  assert.equal(jar.headerFor('http://t.com/'), 'live=2');
  jar.clear();
  jar.setFromResponse('http://t.com/', ['old=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT']);
  assert.equal(jar.headerFor('http://t.com/'), null);
});

test('Secure cookie 仅 https 回发', () => {
  const jar = new CookieJar();
  jar.setFromResponse('https://t.com/', ['s=1; Secure']);
  assert.equal(jar.headerFor('http://t.com/'), null);
  assert.equal(jar.headerFor('https://t.com/'), 's=1');
});

test('path 长度降序回发（RFC 6265 §5.4）', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/admin/x', ['root=1; Path=/', 'deep=2; Path=/admin']);
  assert.equal(jar.headerFor('http://t.com/admin/y'), 'deep=2; root=1');
});

test('mergeInto：用户显式 Cookie 优先，jar 仅补不重名项', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/', ['sid=jarsid', 'extra=1']);
  const headers = { Cookie: 'sid=user' };
  jar.mergeInto(headers, 'http://t.com/scan?id=1');
  assert.equal(headers['Cookie'], 'sid=user; extra=1');
});

test('mergeInto：无显式 Cookie 时直接写入', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/', ['sid=jarsid']);
  const headers = {};
  jar.mergeInto(headers, 'http://t.com/scan?id=1');
  assert.equal(headers['Cookie'], 'sid=jarsid');
});

test('跨域不回发：t.com 的 cookie 不发给 evil.com', () => {
  const jar = new CookieJar();
  jar.setFromResponse('http://t.com/', ['sid=x']);
  assert.equal(jar.headerFor('http://evil.com/'), null);
  assert.equal(jar.headerFor('http://evilt.com/'), null); // 后缀匹配必须带点边界
});

test('非法 set-cookie（无名/畸形）忽略', () => {
  const jar = new CookieJar();
  const n = jar.setFromResponse('http://t.com/', ['novalue', '=empty', 'ok=1; Path=/']);
  assert.equal(n, 1);
});

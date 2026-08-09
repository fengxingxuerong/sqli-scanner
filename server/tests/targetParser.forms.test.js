// TargetParser 表单爬取单元测试：mock HttpClient 取页，解析 <form> + 捕获 CSRF
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const HTML = `<html><body>
<form method="POST" action="/login">
  <input type="text" name="username" value="admin">
  <input type="password" name="password" value="">
  <input type="hidden" name="_token" value="csrf123">
  <input type="submit" name="submit" value="Go">
</form>
<form method="GET" action="/search">
  <input type="text" name="q" value="">
</form>
</body></html>`;

function makeParser(html) {
  const httpClient = { async request() { return { data: html, status: 200 }; } };
  return new TargetParser(httpClient);
}

test('crawlForms 默认关闭：不生成表单点，原有发现不受影响', async () => {
  const parser = makeParser(HTML);
  const target = createTarget({ url: 'http://x.com/page', method: 'GET' });
  // 默认 config.crawlForms=false
  assert.equal(target.config.crawlForms, false);
  const points = await parser.discover(target);
  // url 无查询参数 → 0 个；不应出现任何表单点
  assert.equal(points.length, 0);
  assert.ok(!points.some((p) => p.formMethod !== null));
});

test('crawlForms 开启：解析表单生成 body 点并捕获 CSRF', async () => {
  const parser = makeParser(HTML);
  const target = createTarget({ url: 'http://x.com/page', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const formPoints = points.filter((p) => p.formMethod !== null);
  // form1: username/password/_token（3，submit 跳过）；form2: q（1）→ 共 4 个表单点
  assert.equal(formPoints.length, 4);

  const user = formPoints.find((p) => p.param === 'username');
  assert.equal(user.location, 'body');
  assert.equal(user.formMethod, 'POST');
  assert.equal(user.actionUrl, 'http://x.com/login'); // 相对 action 解析为绝对地址
  assert.equal(user.originalValue, 'admin');
  // 全部字段（含 CSRF token）随表单点携带
  assert.deepEqual(user.formValues, { username: 'admin', password: '', _token: 'csrf123' });
  assert.equal(user.csrfTokenName, '_token');

  const pass = formPoints.find((p) => p.param === 'password');
  assert.equal(pass.formMethod, 'POST');
  assert.equal(pass.formValues._token, 'csrf123');

  const tok = formPoints.find((p) => p.param === '_token');
  assert.equal(tok.formMethod, 'POST');
  assert.equal(tok.csrfTokenName, '_token');

  // GET 表单
  const q = formPoints.find((p) => p.param === 'q');
  assert.equal(q.formMethod, 'GET');
  assert.equal(q.actionUrl, 'http://x.com/search');

  // submit 类控件不应成为注入点
  assert.ok(!formPoints.some((p) => p.param === 'submit'));
});

test('多 action 记为独立点（不同 action 独立）', async () => {
  const html = `<html><body>
  <form method="POST" action="/a"><input type="text" name="x" value="1"></form>
  <form method="POST" action="/b"><input type="text" name="x" value="2"></form>
  </body></html>`;
  const parser = makeParser(html);
  const target = createTarget({ url: 'http://x.com/p', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const xs = points.filter((p) => p.param === 'x');
  assert.equal(xs.length, 2);
  const actions = xs.map((p) => p.actionUrl).sort();
  assert.deepEqual(actions, ['http://x.com/a', 'http://x.com/b']);
});

test('取页失败（HttpClient 抛错）不中断发现，仅无表单点', async () => {
  const httpClient = { async request() { throw new Error('network'); } };
  const parser = new TargetParser(httpClient);
  const target = createTarget({ url: 'http://x.com/page', method: 'GET', bodyParams: { a: '1' } });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  // 原 body 参数仍被发现；表单点因取页失败而不产生
  assert.ok(points.some((p) => p.param === 'a' && p.location === 'body'));
  assert.ok(!points.some((p) => p.formMethod !== null));
});

test('构造签名兼容：不传 httpClient 时用单例（不抛）', () => {
  assert.doesNotThrow(() => new TargetParser());
});

// —— 二阶扩展：POST 表单点标记 isStorePoint / storeKind ——

test('POST 表单点被标记 isStorePoint=true，GET 表单点保持 false', async () => {
  const parser = makeParser(HTML);
  const target = createTarget({ url: 'http://x.com/page', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const formPoints = points.filter((p) => p.formMethod !== null);
  // 表单1 为 POST → 三个字段均 isStorePoint=true
  const user = formPoints.find((p) => p.param === 'username');
  assert.equal(user.isStorePoint, true);
  // 表单2 为 GET → isStorePoint=false，storeKind=null
  const q = formPoints.find((p) => p.param === 'q');
  assert.equal(q.isStorePoint, false);
  assert.equal(q.storeKind, null);
});

test('storeKind 启发式：注册类 POST 表单识别为 registration', async () => {
  const html = `<html><body>
  <form method="POST" action="/register">
    <input type="text" name="username" value="">
    <input type="password" name="password" value="">
    <input type="email" name="email" value="">
  </form></body></html>`;
  const parser = makeParser(html);
  const target = createTarget({ url: 'http://x.com/r', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const user = points.find((p) => p.param === 'username');
  assert.equal(user.isStorePoint, true);
  assert.equal(user.storeKind, 'registration');
});

test('storeKind 启发式：评论类 POST 表单识别为 comment', async () => {
  const html = `<html><body>
  <form method="POST" action="/comment">
    <input type="text" name="author" value="">
    <input type="text" name="comment" value="">
  </form></body></html>`;
  const parser = makeParser(html);
  const target = createTarget({ url: 'http://x.com/c', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const c = points.find((p) => p.param === 'comment');
  assert.equal(c.isStorePoint, true);
  assert.equal(c.storeKind, 'comment');
});

test('storeKind 启发式：资料类 POST 表单识别为 profile', async () => {
  const html = `<html><body>
  <form method="POST" action="/profile">
    <input type="text" name="displayName" value="">
    <input type="text" name="bio" value="">
  </form></body></html>`;
  const parser = makeParser(html);
  const target = createTarget({ url: 'http://x.com/p', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const d = points.find((p) => p.param === 'displayName');
  assert.equal(d.isStorePoint, true);
  assert.equal(d.storeKind, 'profile');
});

test('storeKind 启发式：其它 POST 表单识别为 unknown', async () => {
  const html = `<html><body>
  <form method="POST" action="/search">
    <input type="text" name="query" value="">
  </form></body></html>`;
  const parser = makeParser(html);
  const target = createTarget({ url: 'http://x.com/s', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const q = points.find((p) => p.param === 'query');
  assert.equal(q.isStorePoint, true);
  assert.equal(q.storeKind, 'unknown');
});

test('二阶标记不破坏原有发现（crawlForms 关闭仍无表单点，开启后原字段完整）', async () => {
  const parser = makeParser(HTML);
  const target = createTarget({ url: 'http://x.com/page', method: 'GET' });
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const formPoints = points.filter((p) => p.formMethod !== null);
  // 既有断言仍成立：字段数量、CSRF 捕获、action 解析
  assert.equal(formPoints.length, 4);
  const user = formPoints.find((p) => p.param === 'username');
  assert.deepEqual(user.formValues, { username: 'admin', password: '', _token: 'csrf123' });
  assert.equal(user.csrfTokenName, '_token');
  assert.equal(user.actionUrl, 'http://x.com/login');
  // 且新增字段存在且有默认语义
  assert.equal(user.isStorePoint, true);
  assert.equal(user.storeKind, 'registration');
});

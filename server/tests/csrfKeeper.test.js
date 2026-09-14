// csrfKeeper 单测：token 提取 / 携带形态 / 刷新
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractCsrfToken, withCsrf } from '../src/core/csrfKeeper.js';

const HTML = `
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="abc123">
  <input name="user">
</form>`;

test('extractCsrfToken：显式名精确匹配', () => {
  const hit = extractCsrfToken(HTML, 'csrf_token');
  assert.equal(hit.name, 'csrf_token');
  assert.equal(hit.value, 'abc123');
});

test('extractCsrfToken：自动探测常见名', () => {
  const html = '<input type="hidden" name="_csrf" value="xyz">';
  assert.deepEqual(extractCsrfToken(html, null), { name: '_csrf', value: 'xyz' });
});

test('extractCsrfToken：无 token 返回 null', () => {
  assert.equal(extractCsrfToken('<p>no form</p>', 'csrf_token'), null);
  assert.equal(extractCsrfToken('', 'csrf_token'), null);
});

test('withCsrf：GET 请求 token 入 query，不覆盖已有参数', async () => {
  const seen = [];
  const client = {
    request: async (o) => {
      seen.push(o);
      if (o.url.includes('csrfpage')) return { status: 200, data: HTML };
      return { status: 200, data: 'ok' };
    },
  };
  const wrapped = withCsrf(client, { csrfUrl: 'http://t/csrfpage', csrfTokenName: 'csrf_token', refreshFreq: 100 });
  await wrapped.request({ method: 'GET', url: 'http://t/target?id=1' });
  assert.ok(seen[1].url.includes('csrf_token=abc123'), 'token in query');
  assert.ok(seen[1].url.includes('id=1'), '业务参数保留');
});

test('withCsrf：POST 表单 token 并入 data，业务字段不覆盖', async () => {
  const seen = [];
  const client = {
    request: async (o) => {
      seen.push(o);
      if (o.url.includes('csrfpage')) return { status: 200, data: HTML };
      return { status: 200, data: 'ok' };
    },
  };
  const wrapped = withCsrf(client, { csrfUrl: 'http://t/csrfpage', csrfTokenName: 'csrf_token', refreshFreq: 100 });
  await wrapped.request({ method: 'POST', url: 'http://t/target', data: { user: 'u', csrf_token: 'BUSINESS' } });
  assert.equal(seen[1].data.csrf_token, 'BUSINESS', '业务字段优先');
  await wrapped.request({ method: 'POST', url: 'http://t/target', data: { user: 'u' } });
  assert.equal(seen[2].data.csrf_token, 'abc123', '无业务字段时并入');
});

test('withCsrf：取页失败静默降级 + warn（不阻断扫描）', async () => {
  let called = 0;
  const client = {
    request: async (o) => {
      called++;
      if (o.url.includes('csrfpage')) throw new Error('ECONNREFUSED');
      return { status: 200, data: 'ok' };
    },
  };
  const wrapped = withCsrf(client, { csrfUrl: 'http://t/csrfpage' });
  const res = await wrapped.request({ method: 'GET', url: 'http://t/target' });
  assert.equal(res.status, 200, '扫描请求照常发出');
  assert.equal(called, 2, '取页 1 次 + 扫描 1 次');
});

test('withCsrf：refreshFreq 到期重取 token', async () => {
  const seen = [];
  let fetchCount = 0;
  const client = {
    request: async (o) => {
      if (o.url.includes('csrfpage')) { fetchCount++; return { status: 200, data: `<input name="csrf_token" value="v${fetchCount}">` }; }
      seen.push(o);
      return { status: 200, data: 'ok' };
    },
  };
  const wrapped = withCsrf(client, { csrfUrl: 'http://t/csrfpage', csrfTokenName: 'csrf_token', refreshFreq: 2 });
  await wrapped.request({ method: 'GET', url: 'http://t/a' });  // fetch #1 → v1
  await wrapped.request({ method: 'GET', url: 'http://t/b' });  // count=2 → refresh → v2
  await wrapped.request({ method: 'GET', url: 'http://t/c' });  // v2
  assert.ok(seen[0].url.includes('v1'), '首请求 v1');
  assert.ok(seen[1].url.includes('v2'), '刷新后 v2');
  assert.ok(seen[2].url.includes('v2'), '沿用 v2');
});

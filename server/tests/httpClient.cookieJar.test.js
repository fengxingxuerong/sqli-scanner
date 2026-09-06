// httpClient Cookie Jar 集成回归（[P1-FIX 2026-09-05]）
// 验证 request() 主流程：Set-Cookie 捕获 → 后续请求自动回发 → dropSetCookie 关闭捕获
// → cookieJar=false 关闭回发。传输层用 mock（this.instance.request 桩），
// DNS/SSRF 校验对 http://localhost 目标放行（本地回环为引擎合法目标）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';

function mockClient(responder) {
  const h = new HttpClient();
  const captured = [];
  h.instance = {
    async request(cfg) {
      captured.push({ url: cfg.url, cookie: cfg.headers?.Cookie ?? null });
      return responder(cfg, captured.length);
    },
  };
  return { h, captured };
}

const okRes = (setCookie) => ({ status: 200, headers: setCookie ? { 'set-cookie': setCookie } : {}, data: 'ok' });

test('集成：首响应 Set-Cookie → 第二次请求自动回发 Cookie 头', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=abc; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cj1' });
  assert.equal(captured[0].cookie, null, '首次请求不应带 jar cookie');
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cj1' });
  assert.equal(captured[1].cookie, 'sid=abc', '第二次请求应自动回发 jar cookie');
});

test('集成：dropSetCookie=true 丢弃服务端会话（对标 --drop-set-cookie）', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=abc; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cj2', dropSetCookie: true });
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cj2' });
  assert.equal(captured[1].cookie, null, 'dropSetCookie 开启时不应回发');
});

test('集成：cookieJar=false 关闭自动会话（行为与旧版一致）', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=abc; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cj3', cookieJar: false });
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cj3' });
  assert.equal(captured[1].cookie, null, 'cookieJar 关闭时不应回发');
});

test('集成：用户显式 Cookie 优先，jar 补充不重名项', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=jar; Path=/', 'extra=1; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cj4', headers: { Cookie: 'sid=user' } });
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cj4', headers: { Cookie: 'sid=user' } });
  assert.equal(captured[1].cookie, 'sid=user; extra=1');
});

test('集成：跨 scanId 会话隔离', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=abc; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cjA' });
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cjB' });
  assert.equal(captured[1].cookie, null, '不同扫描的 jar 互不共享');
  h.clearJar('cjA');
  assert.equal(h.jarFor('cjA').size, 0, 'clearJar 应清空对应扫描的 jar');
});

test('集成：clearJar 后不再回发（扫描退役路径）', async () => {
  const { h, captured } = mockClient(() => okRes(['sid=abc; Path=/']));
  await h.request({ url: 'http://localhost:9/a', method: 'GET', scanId: 'cj5' });
  h.clearJar('cj5');
  await h.request({ url: 'http://localhost:9/b', method: 'GET', scanId: 'cj5' });
  assert.equal(captured[1].cookie, null);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient, assertSafeHttpTarget } from '../src/core/httpClient.js';

// ===== [P2-5] --force-ssl =====
test('forceSsl: http:// 目标改写为 https:// 后再发请求', async () => {
  const client = new HttpClient();
  let capturedUrl = null;
  let capturedCfg = null;
  client.instance.request = async (cfg) => {
    capturedCfg = cfg;
    capturedUrl = cfg.url;
    return { data: 'ok', status: 200 };
  };
  const res = await client.request({
    method: 'GET',
    url: 'http://example.com:8080/path?x=1',
    headers: {},
    forceSsl: true,
  });
  assert.ok(res && res.data === 'ok');
  assert.equal(capturedUrl, 'https://example.com:8080/path?x=1');
  assert.equal(capturedCfg.url, 'https://example.com:8080/path?x=1');
});

test('forceSsl: 已是 https 的目标不被改写', async () => {
  const client = new HttpClient();
  let capturedUrl = null;
  client.instance.request = async (cfg) => {
    capturedUrl = cfg.url;
    return { data: '', status: 200 };
  };
  await client.request({ method: 'GET', url: 'https://example.com/a', headers: {}, forceSsl: true });
  assert.equal(capturedUrl, 'https://example.com/a');
});

test('forceSsl: 未开启时不改写（回归护栏）', async () => {
  const client = new HttpClient();
  let capturedUrl = null;
  client.instance.request = async (cfg) => {
    capturedUrl = cfg.url;
    return { data: '', status: 200 };
  };
  await client.request({ method: 'GET', url: 'http://example.com/a', headers: {} });
  assert.equal(capturedUrl, 'http://example.com/a');
});

test('forceSsl: 带端口/查询串的 URL 改写后保留端口与查询', async () => {
  const client = new HttpClient();
  let capturedUrl = null;
  client.instance.request = async (cfg) => {
    capturedUrl = cfg.url;
    return { data: '', status: 200 };
  };
  await client.request({
    method: 'GET',
    url: 'http://example.com:81/x?y=1&z=2#frag',
    headers: {},
    forceSsl: true,
  });
  assert.equal(capturedUrl, 'https://example.com:81/x?y=1&z=2#frag');
});

// ===== [P2-5] --ignore-redirects =====
test('ignoreRedirects: 3xx 响应直接返回不跟随（首跳即 302）', async () => {
  const client = new HttpClient();
  let rawCalls = 0;
  client.instance.request = async () => {
    rawCalls++;
    return { status: 302, headers: { location: 'http://example.com/next' }, data: '' };
  };
  const res = await client.request({
    method: 'GET',
    url: 'http://example.com/start',
    headers: {},
    ignoreRedirects: true,
  });
  assert.equal(res.status, 302);
  assert.equal(rawCalls, 1, '不应继续跟随跳转');
});

test('ignoreRedirects: 未开启时仍跟随跳转（回归护栏：最多 5 跳）', async () => {
  const client = new HttpClient();
  let rawCalls = 0;
  client.instance.request = async () => {
    rawCalls++;
    return { status: 302, headers: { location: 'http://example.com/next' }, data: '' };
  };
  await client.request({ method: 'GET', url: 'http://example.com/start', headers: {} });
  assert.equal(rawCalls, 6, '默认应跟随 5 跳（首跳 + 5 次跳转）');
});

test('ignoreRedirects: http2 路径同样忽略 3xx', async () => {
  const client = new HttpClient();
  client._rawUndici = async () => {
    return { status: 301, headers: { location: 'http://example.com/next' }, data: '' };
  };
  const res = await client.request({
    method: 'GET',
    url: 'http://example.com/start',
    headers: {},
    ignoreRedirects: true,
    http2: true,
  });
  assert.equal(res.status, 301);
});

test('ignoreRedirects: 200 正常响应不受影响', async () => {
  const client = new HttpClient();
  let rawCalls = 0;
  client.instance.request = async () => {
    rawCalls++;
    return { status: 200, headers: {}, data: 'ok' };
  };
  const res = await client.request({
    method: 'GET',
    url: 'http://example.com/start',
    headers: {},
    ignoreRedirects: true,
  });
  assert.equal(res.status, 200);
  assert.equal(rawCalls, 1);
});

// requestFileParser 单测（对标 sqlmap -r）
// 覆盖：Burp 风格 GET 请求、POST 请求 + body、带 Cookie 请求、
//       多 query params 提取、空文件/非法格式降级。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRequestFile } from '../src/core/requestFileParser.js';

// ─────────────── Burp 风格 GET 请求 ───────────────
test('GET 请求 + Host 头 → 拼接完整 URL', () => {
  const text = [
    'GET /num?id=1 HTTP/1.1',
    'Host: 127.0.0.1:8123',
    'User-Agent: Mozilla/5.0',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.method, 'GET');
  assert.equal(r.url, 'http://127.0.0.1:8123/num?id=1');
  assert.equal(r.headers['Host'], '127.0.0.1:8123');
  assert.equal(r.headers['User-Agent'], 'Mozilla/5.0');
  assert.equal(r.body, '');
  assert.deepEqual(r.params, { id: '1' });
});

// ─────────────── POST 请求 + Content-Type + body ───────────────
test('POST 请求 + Content-Type + body → method/body 正确', () => {
  const text = [
    'POST /api/login HTTP/1.1',
    'Host: example.com',
    'Content-Type: application/json',
    '',
    '{"user":"admin","pass":"123"}',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.method, 'POST');
  assert.equal(r.url, 'http://example.com/api/login');
  assert.equal(r.headers['Content-Type'], 'application/json');
  assert.equal(r.body, '{"user":"admin","pass":"123"}');
});

// ─────────────── 带 Cookie 的请求 ───────────────
test('带 Cookie 的请求 → headers 含 Cookie', () => {
  const text = [
    'GET /dashboard HTTP/1.1',
    'Host: example.com',
    'Cookie: session=abc123; theme=dark',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.headers['Cookie'], 'session=abc123; theme=dark');
  // /dashboard 无 query string → params 为空
  assert.deepEqual(r.params, {});
});

// ─────────────── 多 query params 提取 ───────────────
test('多 query params → params 对象含所有参数', () => {
  const text = [
    'GET /search?q=test&page=2&sort=desc HTTP/1.1',
    'Host: example.com',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.url, 'http://example.com/search?q=test&page=2&sort=desc');
  assert.deepEqual(r.params, { q: 'test', page: '2', sort: 'desc' });
});

// ─────────────── 空 / 非法格式 ───────────────
test('空文件 → null', () => {
  assert.equal(parseRequestFile(''), null);
  assert.equal(parseRequestFile('   \n  '), null);
});

test('非法格式（非 HTTP 请求行）→ null', () => {
  assert.equal(parseRequestFile('Hello World'), null);
  assert.equal(parseRequestFile('Some random text\nMore text'), null);
});

test('null / undefined 输入 → null', () => {
  assert.equal(parseRequestFile(null), null);
  assert.equal(parseRequestFile(undefined), null);
});

// ─────────────── 缺 Host 头 + 相对路径 → null ───────────────
test('缺 Host 头且路径非绝对 URL → null', () => {
  const text = [
    'GET /path?id=1 HTTP/1.1',
    '',
  ].join('\r\n');
  assert.equal(parseRequestFile(text), null);
});

// ─────────────── 绝对 URL（带协议）无 Host 也可用 ───────────────
test('绝对 URL 无 Host 头 → 正常解析', () => {
  const text = [
    'GET https://example.com/api?id=1 HTTP/1.1',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.url, 'https://example.com/api?id=1');
  assert.deepEqual(r.params, { id: '1' });
});

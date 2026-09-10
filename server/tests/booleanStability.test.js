// boolean 判定稳定性 + LIKE 闭合 + JSON 响应文本化（P1-FIX 2026-09-08）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import BooleanBlindDetector from '../src/engine/detectors/BooleanBlindDetector.js';
import { Detector } from '../src/engine/Detector.js';
import { HttpClient } from '../src/core/httpClient.js';

const bd = new BooleanBlindDetector();

test('空串不与任何非空响应判相似（空数组 [] / 超时空响应 不再被当作基线）', () => {
  assert.equal(bd._similar('', '[object Object]'), false);
  assert.equal(bd._similar('', '<html>...</html>'), false);
  assert.equal(bd._similar('', ''), true); // 空与空仍相似
});

test('等长且仅数字段不同 → 判相似（秒级时间戳不污染判定）', () => {
  const a = '<html><!-- generated at 1788758518 --><p>same</p></html>';
  const b = '<html><!-- generated at 1788758519 --><p>same</p></html>';
  assert.equal(bd._similar(a, b), true);
});

test('等长但非数字部分不同 → 不判相似（真注入差异不被吞掉）', () => {
  const a = '<html><p>user: alice</p></html>';
  const b = '<html><p>user: bobxx</p></html>';
  assert.equal(bd._similar(a, b), false);
});

test('长度差异显著 → 不判相似（假条件空结果集）', () => {
  assert.equal(bd._similar('x'.repeat(300), 'x'.repeat(100)), false);
});

test('probeBoundary 识别 LIKE 上下文闭合前缀 %\'', async () => {
  const BASE = 'http://t.local/s';
  // mock：仅当注入值以 %' 闭合时才返回「基线同款」页面（模拟 LIKE '%v%' 上下文）
  const baseBody = '<html><title>搜索結果</title><table><tr><td>1</td></tr></table></html>';
  const httpClient = {
    request: async (opts) => {
      const u = new URL(opts.url);
      const q = u.searchParams.get('q') || '';
      return q.includes("%'") || q === '键盘'
        ? { status: 200, data: baseBody }
        : { status: 200, data: '<html><title>搜索結果</title><p>暂无数据</p></html>' };
    },
  };
  const target = { mode: 'http', baseUrl: BASE, method: 'GET', cookieParams: {}, headerParams: {}, config: {} };
  const point = { location: 'url', param: 'q', originalValue: '键盘' };
  const d = new Detector('boolean');
  const boundary = await d.probeBoundary({ httpClient, target, point, config: {} });
  assert.equal(boundary, "%'");
});

test('HttpClient 对 JSON 响应返回原始文本（不被 axios 隐式 parse 成对象）', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, rows: [{ id: 1 }] }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const client = new HttpClient();
  const res = await client.request({ method: 'GET', url: `http://127.0.0.1:${port}/api/item?id=1` });
  assert.equal(typeof res.data, 'string');
  assert.equal(res.data, '{"ok":true,"rows":[{"id":1}]}');
  server.close();
});

test('HttpClient 对空数组 JSON 响应返回 "[]" 而非空串（真假可区分）', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('[]');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const client = new HttpClient();
  const res = await client.request({ method: 'GET', url: `http://127.0.0.1:${port}/api/item?id=1 AND 1=2` });
  assert.equal(res.data, '[]');
  assert.equal(res.data.length, 2);
  server.close();
});

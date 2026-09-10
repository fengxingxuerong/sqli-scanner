// ============================================================================
// tests/httpClient.oversize.test.js —— 响应超限必须快速失败，不得重试放大
// [P1-FIX 2026-09-09]
//
// 实战场景：目标注入点挂在大列表页/导出接口上（首页 3MB、导出页 40MB 很常见）。原实现把
// axios 的 maxContentLength 错误当普通网络错误 → 按 retry 重试 4 次，每次都要「缓冲到上限再丢弃」，
// 结果是：内存与带宽按 (retry+1) 倍白烧、耗时线性放大，而最终错误文案是「HTTP 请求失败」，
// 使用者看不出是「页面太大」还是「目标拒绝」。真实作战里这足以让一次扫描把自己拖垮。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { httpClient } from '../src/core/httpClient.js';

test('超限响应只发 1 次请求（不重试），并给出可判读的原因', async () => {
  let hits = 0;
  const body = 'A'.repeat(200 * 1024); // 200KB
  const server = http.createServer((req, res) => {
    hits++;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(body);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    let err = null;
    let res = null;
    try {
      res = await httpClient.request({
        url: `http://127.0.0.1:${port}/export`,
        method: 'GET',
        maxContentLength: 1024, // 1KB 上限 → 必然超限
        retry: 3,
        timeoutMs: 5000,
      });
    } catch (e) {
      err = e;
    }
    assert.equal(hits, 1, `超限应只发 1 次请求（不重试放大），实际 ${hits} 次`);
    const msg = String(err?.message ?? res?.data ?? '');
    if (err) assert.match(msg, /响应体超过上限/, `错误文案应说明超限原因，实际：${msg}`);
  } finally {
    server.close();
  }
});

test('未超限路径不受影响（正常返回，仍只发 1 次）', async () => {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>small</h1>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const res = await httpClient.request({ url: `http://127.0.0.1:${port}/ok`, method: 'GET', retry: 3 });
    assert.equal(res.status, 200);
    assert.match(String(res.data), /<h1>small<\/h1>/);
    assert.equal(hits, 1);
  } finally {
    server.close();
  }
});

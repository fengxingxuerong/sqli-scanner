// ============================================================================
// tests/scopeGuard.redirect.test.js —— 授权范围「逐跳」生效的真实链路测试
// [P0-SEC 2026-09-08]
//
// 为什么必须写这一条：scope 的入口校验在 sanitizeStart（同步、可单测），但实战里真正的洞是
// 「目标 302 跳到未授权主机」（统一登录跳转 / CDN 回源 / 灰度切流）——扫描器会跟着跳，
// 并把后续全部注入请求连同 Cookie/Authorization 打到圈外。只在路由层校一次拦不住它。
// 本测试用两个真实本地 server：A 在范围内且 302 到 B，断言 B 一次都没被访问过。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { httpClient } from '../src/core/httpClient.js';
import { parseScope, registerScanScope, releaseScanScope } from '../src/core/scopeGuard.js';

function listen(server, host) {
  return new Promise((resolve) => server.listen(0, host, () => resolve(server.address().port)));
}

function makeServer(handler) {
  const state = { hits: 0 };
  const server = http.createServer((req, res) => {
    state.hits++;
    handler(req, res);
  });
  return { server, state };
}

test('scope 启用时：302 跳向圈外主机被拦，圈外 server 零请求', async () => {
  // 圈内用 localhost（本机优先解到 ::1），圈外用 127.0.0.1：两个 server 都真实可达，
  // 这样「圈外零请求」只能是被 scope 拦住，而不是连不上。
  const out = makeServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('SECRET-OUT-OF-SCOPE');
  });
  const outPort = await listen(out.server, '127.0.0.1');

  const inScope = makeServer((req, res) => {
    if (req.url.startsWith('/go')) {
      res.writeHead(302, { Location: `http://127.0.0.1:${outPort}/steal` });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>in scope</h1>');
  });
  const inPort = await listen(inScope.server, '::');

  const scanId = `scope-test-${Date.now()}`;
  // 范围只含 localhost：127.0.0.1 属于圈外（等价于「同机另一个未授权系统」）
  registerScanScope(scanId, parseScope(['=localhost']));
  try {
    const ok = await httpClient.request({
      url: `http://localhost:${inPort}/page?id=1`,
      method: 'GET',
      scanId,
    });
    assert.equal(ok.status, 200, '圈内目标应正常返回');

    // 同一目标 302 到 127.0.0.1：跳转前逐跳校验应拒绝，且请求不得发出。
    // 注：当前 HttpClient 对在途错误统一「吞成 null」（已列入待办 P0-1），故这里不假定报式，
    // 只钉住真正的安全性质：圈外 server 零请求 + 调用方拿不到圈外内容。
    let threw = null;
    let crossed = null;
    try {
      crossed = await httpClient.request({
        url: `http://localhost:${inPort}/go?id=1'`,
        method: 'GET',
        scanId,
      });
    } catch (e) {
      threw = e;
    }
    assert.equal(out.state.hits, 0, `圈外主机不得收到任何请求，实际 ${out.state.hits} 次`);
    if (threw) {
      assert.ok(
        threw.code === 1004 || /授权范围|scope/i.test(String(threw.message)),
        `拒因应是 scope 越界，实际：${threw.message}`
      );
    } else {
      assert.ok(
        crossed == null || crossed.status === 0 || crossed.status >= 400,
        `越界跳转不得拿到正常响应，实际：${JSON.stringify({ status: crossed?.status, data: String(crossed?.data ?? '').slice(0, 40) })}`
      );
    }
  } finally {
    releaseScanScope(scanId);
    inScope.server.close();
    out.server.close();
  }
});

test('scope 未登记时：跳转行为与历史一致（正常跟随）', async () => {
  const dst = makeServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('followed');
  });
  const dstPort = await listen(dst.server, '127.0.0.1');
  const src = makeServer((req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${dstPort}/x` });
    res.end();
  });
  const srcPort = await listen(src.server, '127.0.0.1');
  try {
    const res = await httpClient.request({ url: `http://127.0.0.1:${srcPort}/`, method: 'GET' });
    assert.equal(res.status, 200);
    assert.match(String(res.data), /followed/, '无 scope 时仍应跟随重定向（零行为变化）');
  } finally {
    src.server.close();
    dst.server.close();
  }
});

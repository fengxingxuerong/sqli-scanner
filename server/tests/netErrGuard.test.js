// [P0-FIX 2026-09-09] 网络失败不得被解释为「目标没有注入」
// 背景（实测）：装了系统代理（HTTP_PROXY 非空、NO_PROXY 为空）的机器上扫 127.0.0.1 靶场时，
// 代理对部分请求失败 → 该注入点所有检测器抛错 → runLayer 的 catch 一律记「已检测、0 漏洞」。
// 同一份代码在有无代理时结论不同（19/19 ↔ 18/19 的二阶假阴性）。本文件固化两层防线：
//   ① resolveProxy：本地/私网目标默认不吃环境变量代理（curl 同语义）；
//   ② ScanValidityGuard.addNetworkErrorPoint：全层网络失败的点记入未决 → reliable=false。
import test from 'node:test';
import assert from 'node:assert/strict';
import { ScanValidityGuard, isNetworkFailureError } from '../src/core/scanValidityGuard.js';
import { resolveProxy, isLocalOrPrivateHost } from '../src/core/httpClient.js';

const ENV_KEYS = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'NO_PROXY', 'no_proxy'];

test('isNetworkFailureError：识别传输层失败，不误伤业务异常与用户取消', () => {
  assert.equal(isNetworkFailureError({ code: 3001, message: '请求超时' }), true, 'HTTP_TIMEOUT');
  assert.equal(isNetworkFailureError({ code: 3002, message: 'HTTP 请求失败' }), true, 'HTTP_ERROR');
  assert.equal(isNetworkFailureError({ code: 'ECONNREFUSED' }), true);
  assert.equal(isNetworkFailureError({ code: 'ENOTFOUND' }), true);
  assert.equal(isNetworkFailureError(new Error('socket hang up')), true, '代理掐断连接');
  assert.equal(isNetworkFailureError(new Error('timeout of 12000ms exceeded')), true);
  // 业务/代码异常不应被当成网络失败（否则真漏检会被洗成「目标不可达」）
  assert.equal(isNetworkFailureError(new TypeError("Cannot read properties of undefined (reading 'x')")), false);
  assert.equal(isNetworkFailureError(new Error('payload 模板缺少占位符')), false);
  // 用户主动 stop：不是目标故障
  assert.equal(isNetworkFailureError({ name: 'AbortError' }), false);
  assert.equal(isNetworkFailureError(null), false);
});

test('isLocalOrPrivateHost：本地与私网命中，公网域名不命中', () => {
  for (const h of ['localhost', '127.0.0.1', '127.9.9.9', '::1', '10.2.3.4', '192.168.1.9', '172.16.0.1', '172.31.255.255', '169.254.169.254']) {
    assert.equal(isLocalOrPrivateHost(h), true, `${h} 应视为本地/私网`);
  }
  for (const h of ['example.com', '8.8.8.8', '172.32.0.1', '11.0.0.1', '']) {
    assert.equal(isLocalOrPrivateHost(h), false, `${h} 不应视为本地/私网`);
  }
});

test('resolveProxy：本地/私网目标默认绕过环境变量代理', () => {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  try {
    process.env.HTTP_PROXY = 'http://127.0.0.1:60124';
    const local = resolveProxy(false, { targetUrl: 'http://127.0.0.1:8125/store' });
    assert.equal(local.proxyUrl, null, '本地目标不应吃环境变量代理');
    assert.equal(local.source, null);

    const priv = resolveProxy(false, { targetUrl: 'http://10.0.0.5:8080/?id=1' });
    assert.equal(priv.proxyUrl, null, '私网目标不应吃环境变量代理');

    const publicHost = resolveProxy(false, { targetUrl: 'http://example.com/?id=1' });
    assert.equal(publicHost.proxyUrl, 'http://127.0.0.1:60124', '公网目标仍按环境变量走代理');
    assert.equal(publicHost.source, 'env');

    // 显式配置是用户意图（要连本地 Burp），不受本地豁免影响
    const explicit = resolveProxy('http://127.0.0.1:8080', { targetUrl: 'http://127.0.0.1:8125/store' });
    assert.equal(explicit.proxyUrl, 'http://127.0.0.1:8080', '显式配置代理优先');
    assert.equal(explicit.source, 'config');
  } finally {
    for (const k of ENV_KEYS) {
      delete process.env[k];
      if (saved[k] !== undefined) process.env[k] = saved[k];
    }
  }
});

test('ScanValidityGuard：网络失败点计入 netErrPoints 且推翻可靠度', () => {
  const g = new ScanValidityGuard();
  // 若干次正常响应：目标可达（不触发 unreachable/blocked 等阈值）
  for (let i = 0; i < 12; i += 1) g.observe({ res: { status: 200, headers: {}, data: 'ok' } });
  let s = g.summary();
  assert.equal(s.reliable, true, '纯正常样本应可靠');
  assert.equal(s.counts.netErrPoints, 0);

  g.addNetworkErrorPoint('p1');
  g.addNetworkErrorPoint('p1'); // 幂等：同点只记一次
  g.addNetworkErrorPoint('p2');
  s = g.summary();
  assert.equal(s.counts.netErrPoints, 2, '两个点各记一次');
  assert.equal(s.reliable, false, '存在未测成的点 → 阴性结论不可信');
  assert.deepEqual(s.inconclusivePoints.sort(), ['p1', 'p2']);
  assert.match(s.reason, /网络层失败/);
  assert.match(s.advice, /NO_PROXY|出口路径/);
  // 状态本身不升级（阈值体系不动），只是可靠度降级
  assert.equal(s.status, 'ok');
});

test('ScanValidityGuard：无网络失败时行为与历史一致（零回归）', () => {
  const g = new ScanValidityGuard();
  for (let i = 0; i < 5; i += 1) g.observe({ res: { status: 200, headers: {}, data: 'ok' } });
  const s = g.summary();
  assert.equal(s.reliable, true);
  assert.equal(s.status, 'ok');
  assert.equal(s.counts.netErrPoints, 0);
  assert.deepEqual(s.inconclusivePoints, []);
});

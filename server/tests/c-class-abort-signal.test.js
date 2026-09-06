import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HttpClient } from '../src/core/httpClient.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// ─── 工具：创建慢速本地 HTTP 服务器（响应延迟 5s，用于验证 abort 提前中断） ───
let slowServer;
let slowBaseUrl;

before(async () => {
  slowServer = http.createServer((req, res) => {
    // 模拟慢请求：5 秒后才响应
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('slow-response');
    }, 5000);
  });
  await new Promise((resolve) => slowServer.listen(0, '127.0.0.1', resolve));
  const addr = slowServer.address();
  slowBaseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise((resolve) => slowServer.close(resolve));
});

// ─── 辅助：创建最小 ScanManager mock（不走构造函数，避免 parser/config 依赖） ───
function mockScanManager() {
  const sm = Object.create(ScanManager.prototype);
  sm.scans = new Map();
  sm._retire = () => {}; // mock：不真正回收
  return sm;
}

// ─── 1. AbortController signal 链路 ───
describe('[C-15] AbortController signal 链路', () => {
  test('abort() 后 signal.aborted === true', () => {
    const ac = new AbortController();
    assert.equal(ac.signal.aborted, false);
    ac.abort();
    assert.equal(ac.signal.aborted, true);
  });

  test('signal 已 aborted 时 request 循环开头直接抛出（不发请求）', async () => {
    const client = new HttpClient();
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(
      () => client.request({ url: `${slowBaseUrl}/test`, signal: ac.signal, retry: 3 }),
      (err) => {
        assert.ok(
          err.name === 'AbortError' || err.code === 'ERR_CANCELED',
          `期望 AbortError，实际 ${err.name}/${err.code}`
        );
        return true;
      }
    );
  });

  test('在途请求被 abort 中断（远早于 5s 超时）', async () => {
    const client = new HttpClient();
    const ac = new AbortController();
    const t0 = Date.now();
    // 发出请求后 200ms abort
    const reqPromise = client.request({
      url: `${slowBaseUrl}/slow`,
      signal: ac.signal,
      retry: 0,
      timeoutMs: 10000,
    });
    setTimeout(() => ac.abort(), 200);
    await assert.rejects(
      () => reqPromise,
      (err) => {
        const elapsed = Date.now() - t0;
        // 应在 2s 内被中断（远早于 5s 响应或 10s 超时）
        assert.ok(elapsed < 2000, `abort 应在 2s 内生效，实际 ${elapsed}ms`);
        assert.ok(
          err.name === 'AbortError' ||
            err.name === 'CanceledError' ||
            err.code === 'ERR_CANCELED' ||
            err.code === 'ABORT_ERR',
          `期望 abort 相关错误，实际 ${err.name}/${err.code}`
        );
        return true;
      }
    );
  });

  test('AbortError 不触发重试（retry=3 但循环开头就 break）', async () => {
    const client = new HttpClient();
    const ac = new AbortController();
    let callCount = 0;
    const interceptorId = client.instance.interceptors.request.use((config) => {
      callCount++;
      return config;
    });
    ac.abort();
    try {
      await client.request({ url: `${slowBaseUrl}/test`, signal: ac.signal, retry: 3 });
    } catch {
      // 预期抛出
    }
    client.instance.interceptors.request.eject(interceptorId);
    // signal 已 aborted，循环开头 break，不应该发任何请求
    assert.equal(callCount, 0, `signal 已 aborted 不应发出请求，实际发了 ${callCount} 次`);
  });

  test('无 signal 时正常请求不受影响', async () => {
    const client = new HttpClient();
    await assert.rejects(
      () => client.request({ url: `${slowBaseUrl}/test`, retry: 0, timeoutMs: 200 }),
      (err) => {
        // httpClient 包装超时为 AppError(HTTP_TIMEOUT) 或保留原始 ECONNABORTED
        const msg = err.message || '';
        assert.ok(
          err.code === 'ECONNABORTED' ||
          /timeout|超时/i.test(msg),
          `期望超时错误，实际 ${err.code}/${msg}`
        );
        // 确保不是 AbortError
        assert.ok(err.name !== 'AbortError' && err.code !== 'ERR_CANCELED',
          '无 signal 不应产生 AbortError');
        return true;
      }
    );
  });
});

// ─── 2. ScanManager abortController / getSignal / _wrapWithSignal ───
describe('[C-15] ScanManager abort 机制', () => {
  test('scans 记录含 abortController 且初始未 aborted', () => {
    const sm = mockScanManager();
    const scanId = 'test-abort-1';
    sm.scans.set(scanId, {
      target: {}, report: {}, status: 'running', cancelled: false,
      createdAt: Date.now(), abortController: new AbortController(),
    });
    const s = sm.scans.get(scanId);
    assert.ok(s.abortController instanceof AbortController);
    assert.equal(s.abortController.signal.aborted, false);
  });

  test('stop() 触发 abort，signal.aborted === true', () => {
    const sm = mockScanManager();
    const scanId = 'test-abort-2';
    sm.scans.set(scanId, {
      target: {}, report: {}, status: 'running', cancelled: false, paused: false,
      createdAt: Date.now(), abortController: new AbortController(),
    });
    sm.stop(scanId);
    const s = sm.scans.get(scanId);
    assert.equal(s.cancelled, true);
    assert.equal(s.status, 'stopped');
    assert.equal(s.abortController.signal.aborted, true);
  });

  test('getSignal() 返回正确 signal', () => {
    const sm = mockScanManager();
    const scanId = 'test-abort-3';
    const ac = new AbortController();
    sm.scans.set(scanId, { abortController: ac });
    assert.equal(sm.getSignal(scanId), ac.signal);
    assert.equal(sm.getSignal('nope'), null);
  });

  test('_wrapWithSignal 包装 client.request 注入 signal', async () => {
    const sm = mockScanManager();
    const scanId = 'test-abort-4';
    const ac = new AbortController();
    sm.scans.set(scanId, { abortController: ac });
    let receivedOpts = null;
    const mockClient = {
      otherProp: 'preserved',
      request: async (opts) => { receivedOpts = opts; return { status: 200, data: 'ok' }; },
    };
    const wrapped = sm._wrapWithSignal(scanId, mockClient);
    assert.equal(wrapped.otherProp, 'preserved');
    await wrapped.request({ url: 'http://example.com' });
    assert.equal(receivedOpts.signal, ac.signal, 'signal 应被注入到 opts');
  });

  test('_wrapWithSignal 无 abortController 时返回原 client', () => {
    const sm = mockScanManager();
    const mockClient = { request: async () => {} };
    const wrapped = sm._wrapWithSignal('nope', mockClient);
    assert.equal(wrapped, mockClient, '无 signal 时应返回原 client 不包装');
  });

  test('stop() 后通过 _wrapWithSignal 发出的请求被中断', async () => {
    const sm = mockScanManager();
    const scanId = 'test-abort-5';
    sm.scans.set(scanId, {
      target: {}, report: {}, status: 'running', cancelled: false, paused: false,
      createdAt: Date.now(), abortController: new AbortController(),
    });
    const client = new HttpClient();
    const wrapped = sm._wrapWithSignal(scanId, client);
    sm.stop(scanId); // 触发 abort
    await assert.rejects(
      () => wrapped.request({ url: `${slowBaseUrl}/test`, retry: 0 }),
      (err) => {
        assert.ok(
          err.name === 'AbortError' ||
            err.name === 'CanceledError' ||
            err.code === 'ERR_CANCELED' ||
            err.code === 'ABORT_ERR',
          `期望 abort 错误，实际 ${err.name}/${err.code}`
        );
        return true;
      }
    );
  });
});

// ─── 3. scanRunner ctxBase signal 注入验证 ───
describe('[C-15] scanRunner ctxBase signal 注入', () => {
  test('ctxBase.httpClient.request 自动透传 signal', async () => {
    // 模拟 scanRunner ctxBase 构造逻辑
    const ac = new AbortController();
    const scanSignal = ac.signal;
    let receivedOpts = null;
    const innerClient = {
      request: async (opts) => { receivedOpts = opts; return { status: 200 }; },
    };
    // 构造与 scanRunner 相同的 wrapper
    const ctxBase = {
      httpClient: {
        ...innerClient,
        request: async (opts) => {
          const res = await innerClient.request(scanSignal ? { ...opts, signal: scanSignal } : opts);
          return res;
        },
      },
      config: {},
      ...(scanSignal ? { signal: scanSignal } : {}),
    };
    assert.ok(ctxBase.signal, 'ctxBase 应暴露 signal 字段');
    await ctxBase.httpClient.request({ url: 'http://example.com' });
    assert.equal(receivedOpts.signal, ac.signal, 'wrapper 应注入 signal 到 opts');
  });
});

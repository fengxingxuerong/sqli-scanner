// 运维开关 --proxy / --timeout / --retries 行为测试
//
// 覆盖现有 httpClient.p2.test.js 未触及的部分：
//  1) HttpClient 把 timeoutMs 透传为 axios 的 timeout 字段
//  2) HttpClient 对"非超时"错误按 retry 次数重试（总尝试 = retry + 1）
//  3) retry=0 时不重试（仅 1 次尝试）
//  4) sendInjection 把 config.timeoutMs/retry/proxy 透传给 httpClient（中间层）
//
// 引擎 HttpClient 已真实实现这三者（per-request 从 opts 读取），本测试做确定性行为断言；
// CLI 层仅透传（cli.js 把 --timeout 秒转毫秒、--retries → config.retry、--proxy → config.proxy），
// 由真实靶机冒烟另行验证端到端可用。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';
import { sendInjection } from '../src/engine/injection.js';

function connResetError() {
  const e = new Error('socket hang up');
  e.code = 'ECONNRESET';
  return e;
}

// ===== 1. timeoutMs 透传为 axios timeout =====
test('HttpClient: timeoutMs 透传为 axios timeout 字段', async () => {
  const client = new HttpClient();
  let captured = null;
  client.instance.request = async (cfg) => {
    captured = cfg;
    return { status: 200, data: 'ok', headers: {} };
  };
  await client.request({ method: 'GET', url: 'http://x/', timeoutMs: 1234 });
  assert.equal(captured.timeout, 1234, '应把 timeoutMs 原样透传为 axios timeout');
});

// ===== 2. retry 非超时错误 → 总尝试 = retry + 1 =====
test('HttpClient: 非超时错误按 retry+1 次尝试', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => {
    calls++;
    throw connResetError();
  };
  await assert.rejects(() => client.request({ method: 'GET', url: 'http://x/', retry: 2 }));
  assert.equal(calls, 3, 'retry=2 应总尝试 3 次（初始 + 2 重试）');
});

// ===== 3. retry=0 不重试 =====
test('HttpClient: retry=0 时仅尝试 1 次', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => {
    calls++;
    throw connResetError();
  };
  await assert.rejects(() => client.request({ method: 'GET', url: 'http://x/', retry: 0 }));
  assert.equal(calls, 1, 'retry=0 不应重试');
});

// ===== 4. sendInjection 透传 config.timeoutMs/retry/proxy 给 httpClient =====
test('sendInjection 透传 config.timeoutMs/retry/proxy 给 httpClient', async () => {
  let captured = null;
  const mockHttpClient = {
    async request(o) {
      captured = o;
      return { status: 200, data: 'ok', headers: {} };
    },
  };
  const ctx = {
    config: { timeoutMs: 30000, retry: 5, proxy: 'http://1.2.3.4:8080' },
  };
  await sendInjection(mockHttpClient, ctx, { url: 'http://x/', method: 'GET' });
  assert.equal(captured.timeoutMs, 30000, 'timeoutMs 应透传');
  assert.equal(captured.retry, 5, 'retry 应透传');
  assert.equal(captured.proxy, 'http://1.2.3.4:8080', 'proxy 应透传');
});

// ===== 5. sendInjection 缺省 config 时回退引擎默认值（不抛错）=====
test('sendInjection 缺省 config 时使用 defaults（timeoutMs/retry 缺省）', async () => {
  let captured = null;
  const mockHttpClient = {
    async request(o) {
      captured = o;
      return { status: 200, data: 'ok', headers: {} };
    },
  };
  const ctx = { config: {} }; // 空 config，应回退 defaults（不抛异常）
  await sendInjection(mockHttpClient, ctx, { url: 'http://x/', method: 'GET' });
  assert.equal(captured.timeoutMs, undefined); // 未设 → opts.timeoutMs ?? config.timeoutMs = undefined
  // retry 经 opts.retry ?? config.retry，config.retry 未设 → undefined；HttpClient 内部再 ?? defaults.retry
  assert.equal(captured.retry, undefined);
  assert.equal(captured.proxy, false); // 默认不走代理
});

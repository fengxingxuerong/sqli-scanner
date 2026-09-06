// Scheduler 令牌桶 / WafIdentifier.shouldAutoRetry 测试
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient } from '../src/core/httpClient.js';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { Scheduler } from '../src/services/Scheduler.js';

// ===== TokenBucket 限速（通过 HttpClient 暴露）=====
test('TokenBucket: 默认桶不阻塞（ratePerSec 足够高）', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => { calls++; return { status: 200, data: '' }; };
  await Promise.all(Array.from({ length: 5 }, () => client.request({ url: 'http://127.0.0.1:9999/', headers: {} })));
  assert.equal(calls, 5);
});

test('TokenBucket: createBucket 后桶独立', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => { calls++; return { status: 200, data: '' }; };
  client.createBucket('test-bucket', 1000);
  await Promise.all(Array.from({ length: 3 }, () => client.request({ url: 'http://127.0.0.1:9999/', scanId: 'test-bucket' })));
  assert.equal(calls, 3);
  client.removeBucket('test-bucket');
});

test('TokenBucket: 慢桶限速生效（10 req/s 发 11 个 ≈100ms）', async () => {
  const client = new HttpClient();
  let calls = 0;
  client.instance.request = async () => { calls++; return { status: 200, data: '' }; };
  client.createBucket('slow', 10);
  const t0 = Date.now();
  await Promise.all(Array.from({ length: 11 }, () => client.request({ url: 'http://127.0.0.1:9999/', scanId: 'slow' })));
  const ms = Date.now() - t0;
  assert.ok(ms >= 80, `慢桶应限速（11 个@10req/s ≥100ms），实际 ${ms}ms`);
  assert.equal(calls, 11);
  client.removeBucket('slow');
});

test('TokenBucket: 独立桶互不干扰', async () => {
  const client = new HttpClient();
  client.instance.request = async () => ({ status: 200, data: '' });
  client.createBucket('slow2', 10);
  client.createBucket('fast', 1000);
  const t0 = Date.now();
  await Promise.all(Array.from({ length: 11 }, () => client.request({ url: 'http://127.0.0.1:9999/', scanId: 'slow2' })));
  const slowMs = Date.now() - t0;
  const t1 = Date.now();
  await Promise.all(Array.from({ length: 11 }, () => client.request({ url: 'http://127.0.0.1:9999/', scanId: 'fast' })));
  const fastMs = Date.now() - t1;
  assert.ok(slowMs >= 80, `慢桶限速 ${slowMs}ms`);
  assert.ok(fastMs < 500, `快桶不应被拖累 ${fastMs}ms`);
  client.removeBucket('slow2');
  client.removeBucket('fast');
});

// ===== Scheduler.run 重试行为 =====
test('Scheduler.run: 空列表直接返回', async () => {
  const s = new Scheduler(4, 100);
  let called = false;
  await s.run([], () => { called = true; });
  assert.equal(called, false);
});

test('Scheduler.run: 成功 item 不重试', async () => {
  const s = new Scheduler(2, 100);
  let count = 0;
  await s.run([1, 2], async (x) => { count++; });
  assert.equal(count, 2);
});

test('Scheduler.run: 失败 item 被重试 retry 次', async () => {
  const s = new Scheduler(1, 100, { retryBackoffMs: 10, retryBackoffMaxMs: 50 });
  let attempts = 0;
  await s.run(['x'], async () => {
    attempts++;
    if (attempts <= 2) throw new Error('fail');
  }, 2);
  assert.equal(attempts, 3, '应重试 2 次（共 3 次尝试）');
});

test('Scheduler.run: retry=0 不重试', async () => {
  const s = new Scheduler(1, 100);
  let attempts = 0;
  await s.run(['x'], async () => {
    attempts++;
    throw new Error('fail');
  }, 0);
  assert.equal(attempts, 1, 'retry=0 应只尝试 1 次');
});

// ===== WafIdentifier.shouldAutoRetry =====
const wafId = new WafIdentifier();

test('shouldAutoRetry: autoRetry=false 返回 false', () => {
  assert.equal(wafId.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], { wafEvasion: { autoRetry: false } }), false);
});

test('shouldAutoRetry: autoRetry 缺省返回 false', () => {
  assert.equal(wafId.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], {}), false);
});

test('shouldAutoRetry: 用户显式配置 tamper 时返回 false', () => {
  assert.equal(
    wafId.shouldAutoRetry(
      [{ vendor: 'Cloudflare', confidence: 0.9 }],
      { wafEvasion: { autoRetry: true, tamper: { enabled: true, plugins: ['space2comment'] } } }
    ),
    false
  );
});

test('shouldAutoRetry: 无高置信 WAF 时返回 false', () => {
  assert.equal(
    wafId.shouldAutoRetry(
      [{ vendor: 'Generic', confidence: 0.5 }],
      { wafEvasion: { autoRetry: true } }
    ),
    false
  );
});

test('shouldAutoRetry: 空候选列表返回 false', () => {
  assert.equal(wafId.shouldAutoRetry([], { wafEvasion: { autoRetry: true } }), false);
});

test('shouldAutoRetry: 满足所有条件时返回 true', () => {
  assert.equal(
    wafId.shouldAutoRetry(
      [{ vendor: 'Cloudflare', confidence: 0.9 }],
      { wafEvasion: { autoRetry: true } }
    ),
    true
  );
});

test('shouldAutoRetry: 仅 userTamperExplicit 阻止（tamper.enabled=false 不阻止）', () => {
  // tamper.enabled=false 且 plugins 为空 → 用户未显式配置 → 不应阻止自动重跑
  assert.equal(
    wafId.shouldAutoRetry(
      [{ vendor: 'Cloudflare', confidence: 0.9 }],
      { wafEvasion: { autoRetry: true, tamper: { enabled: false, plugins: [] } } }
    ),
    true
  );
});
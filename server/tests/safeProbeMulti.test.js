import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SafeProbeClient } from '../src/core/SafeProbeClient.js';

// 多安全 URL 可控 inner：按 url 返回稳定响应，记录被访问的 safe url 顺序
// driftUrl + driftAfter：该 URL 前 driftAfter 次（含基线抓取）返回正常，之后返回 403（模拟突然被拦）
function makeMultiInner(urls, { driftUrl = null, driftAfter = Infinity, perUrl = {} } = {}) {
  const seen = [];
  const counters = new Map(); // url -> 被调用次数
  return {
    seen,
    async request(opts) {
      if (urls.includes(opts.url)) {
        seen.push(opts.url);
        const n = (counters.get(opts.url) || 0) + 1;
        counters.set(opts.url, n);
        // 指定 URL 在 driftAfter 次之后偏离（前 driftAfter 次含基线抓取保持正常）
        if (driftUrl && opts.url === driftUrl && n > driftAfter) {
          return { status: 403, data: 'BLOCKED' };
        }
        const cfg = perUrl[opts.url] || {};
        return { status: cfg.status ?? 200, data: cfg.body ?? `STABLE_${opts.url}` };
      }
      return { status: 200, data: 'REAL' };
    },
  };
}

test('多 safe-url → 合并去重，默认启用随机轮询', () => {
  const inner = makeMultiInner(['http://s1/', 'http://s2/']);
  const c = new SafeProbeClient(inner, {
    safeUrls: ['http://s1/', 'http://s1/', 'http://s2/'],
    safeFreq: 1,
  });
  assert.equal(c.enabled, true);
  assert.deepEqual(c.safeUrls, ['http://s1/', 'http://s2/']); // 去重后两个
});

test('向后兼容：单 safeUrl 字符串仍可用，safeUrls[0] 等于它', () => {
  const c = new SafeProbeClient(makeMultiInner(['http://x/']), { safeUrl: 'http://x/', safeFreq: 1 });
  assert.equal(c.safeUrl, 'http://x/');
  assert.deepEqual(c.safeUrls, ['http://x/']);
});

test('随机轮询：多次探测覆盖所有安全 URL（至少每个都被访问到）', async () => {
  const urls = ['http://s1/', 'http://s2/', 'http://s3/'];
  const inner = makeMultiInner(urls);
  const c = new SafeProbeClient(inner, {
    safeUrls: urls,
    safeFreq: 1, // 每次真实请求都探一次
    randomize: true,
  });
  // 发 60 次真实请求 → 60 次探测（含首次逐个基线懒抓 + 后续随机）
  for (let i = 0; i < 60; i++) await c.request({ url: `http://real/?q=${i}` });
  // 每个安全 URL 都应至少被访问过（覆盖性，随机足够多次应命中全部）
  for (const u of urls) {
    assert.ok(inner.seen.includes(u), `随机轮询应覆盖 ${u}`);
  }
});

test('顺序轮询：--safe-order（randomize=false）→ 探测按 urls 顺序循环', async () => {
  const urls = ['http://s1/', 'http://s2/', 'http://s3/'];
  const inner = makeMultiInner(urls);
  const c = new SafeProbeClient(inner, {
    safeUrls: urls,
    safeFreq: 1,
    randomize: false,
  });
  for (let i = 0; i < 9; i++) await c.request({ url: `http://real/?q=${i}` });
  // 每次探测对 URL 调用两次（基线懒抓 + 实际比对），顺序轮询下每轮 seen 为 [s1,s1,s2,s2,s3,s3]。
  // 断言每 URL 的"实际比对调用"（偶数位）严格按 s1,s2,s3,s1... 循环
  assert.equal(inner.seen[0], 'http://s1/');
  assert.equal(inner.seen[2], 'http://s2/');
  assert.equal(inner.seen[4], 'http://s3/');
  assert.equal(inner.seen[6], 'http://s1/'); // 第二轮回到 s1
});

test('多 URL 中单个基线抓取失败 → 仅禁用该 URL，其他仍探测且不误报', async () => {
  // s2 永远抛错（基线抓不到）；s1 稳定
  const urls = ['http://s1/', 'http://s2/'];
  const inner = {
    seen: [],
    async request(opts) {
      if (opts.url === 'http://s2/') throw new Error('conn refused');
      if (opts.url === 'http://s1/') { this.seen.push(opts.url); return { status: 200, data: 'STABLE_s1' }; }
      return { status: 200, data: 'REAL' };
    },
  };
  const alerts = [];
  const c = new SafeProbeClient(inner, {
    safeUrls: urls,
    safeFreq: 1,
    randomize: false, // 顺序，便于断言 s1 稳定
    onAnomaly: (info) => alerts.push(info),
  });
  for (let i = 0; i < 10; i++) await c.request({ url: `http://real/?q=${i}` });
  // s2 基线失败被禁用 → 不应被再次访问；s1 仍稳定访问且无告警
  assert.ok(!inner.seen.includes('http://s2/'), 's2 基线失败应被禁用，不再访问');
  assert.equal(alerts.length, 0, 's1 稳定 → 不应告警');
  // 后续探测只能落在 s1
  for (let i = 10; i < 20; i++) await c.request({ url: `http://real/?q=${i}` });
  assert.ok(inner.seen.every((u) => u === 'http://s1/'), '禁用 s2 后所有探测只走 s1');
});

test('多 URL 单个偏离 → 仅该 URL 触发告警，主请求仍透传', async () => {
  const urls = ['http://s1/', 'http://s2/'];
  // s2 基线抓取（第 1 次）正常、第 2 次起偏离（403）→ 模拟"稳定后被拦"
  const inner = makeMultiInner(urls, { driftUrl: 'http://s2/', driftAfter: 1 });
  const alerts = [];
  const c = new SafeProbeClient(inner, {
    safeUrls: urls,
    safeFreq: 1,
    randomize: false,
    onAnomaly: (info) => alerts.push(info),
  });
  for (let i = 0; i < 4; i++) await c.request({ url: `http://real/?q=${i}` });
  // s2 第二次访问（实际比对）偏离 → 应告警
  assert.ok(alerts.some((a) => a.url === 'http://s2/'), 's2 偏离应告警');
  // s1 不应告警
  assert.ok(!alerts.some((a) => a.url === 'http://s1/'), 's1 稳定不应告警');
});

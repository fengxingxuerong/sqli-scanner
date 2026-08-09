import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SafeProbeClient } from '../src/core/SafeProbeClient.js';

// 可控 inner：按 url 前缀返回响应；safeUrl 的首探与后续可配置不同（模拟偏离）
function makeInner({ safeBody = 'STABLE_OK_PAGE', safeStatus = 200, driftAfter = Infinity, realBody = 'REAL' } = {}) {
  let safeCalls = 0;
  return {
    async request(opts) {
      if (opts.url.startsWith('http://safe/')) {
        safeCalls += 1;
        const drift = safeCalls > driftAfter; // 超过阈值后内容/状态码偏离
        return {
          status: drift ? (safeStatus === 200 ? 403 : safeStatus) : safeStatus,
          data: drift ? 'BLOCKED_BY_WAF' : safeBody,
        };
      }
      // 真实请求：URL 含 inject 标记则视为注入响应（盲注用）
      return { status: 200, data: realBody };
    },
  };
}

test('未配置 safeUrl → 完全透传，无探测、无计数副作用', async () => {
  const inner = makeInner();
  const c = new SafeProbeClient(inner, {}); // 无 safeUrl → enabled=false
  assert.equal(c.enabled, false);
  const r = await c.request({ url: 'http://real/?q=1' });
  assert.equal(r.data, 'REAL');
  // 任意次数都不触发探测
  for (let i = 0; i < 10; i++) await c.request({ url: 'http://real/?q=1' });
  assert.equal(c.count, 11);
});

test('配置 safeFreq=3 → 每 3 次真实请求穿插一次安全探测，主请求照常返回', async () => {
  const inner = makeInner();
  const probes = [];
  const c = new SafeProbeClient(inner, {
    safeUrl: 'http://safe/',
    safeFreq: 3,
    onProbe: (p) => { probes.push(p); },
  });
  assert.equal(c.enabled, true);
  for (let i = 0; i < 9; i++) {
    const r = await c.request({ url: `http://real/?q=${i}` });
    assert.equal(r.data, 'REAL'); // 主请求透传
  }
  // 首次探测前懒抓基线（baseline:true），第 3、6、9 次穿插实际探测 → 非基线探测 3 次
  const realProbes = probes.filter((p) => !p.baseline);
  assert.equal(realProbes.length, 3);
  assert.equal(c.count, 9);
});

test('安全 URL 偏离基线 → 触发 onAnomaly，且主请求不被阻断', async () => {
  const inner = makeInner({ driftAfter: 2 }); // 基线 + 首次探测稳定，第二次探测开始偏离
  const alerts = [];
  const c = new SafeProbeClient(inner, {
    safeUrl: 'http://safe/',
    safeFreq: 2,
    onAnomaly: (info) => alerts.push(info),
  });
  // 发 4 次真实请求 → 第 2、4 次前探测（探 1=基线正常，探 2=偏离）
  for (let i = 0; i < 4; i++) {
    const r = await c.request({ url: `http://real/?q=${i}` });
    assert.equal(r.data, 'REAL'); // 主请求必须返回，安全探测异常不阻断
  }
  assert.equal(alerts.length, 1); // 仅 1 次偏离
  assert.match(alerts[0].reason, /状态码偏离|响应体长度偏离/);
  assert.equal(alerts[0].baseline?.status, 200);
  assert.equal(alerts[0].actual?.status, 403);
});

test('compare 准则：仅响应体长度小幅度抖动不误报', () => {
  const c = new SafeProbeClient(makeInner(), { safeUrl: 'http://safe/', safeFreq: 1 });
  const base = { status: 200, body: 'A'.repeat(1000) };
  // 长度变化 10%（< 30% 且 < 200 字节）→ 不算偏离
  assert.equal(c._compare(base, { status: 200, body: 'A'.repeat(1050) }), true);
  // 长度变化 50% → 偏离
  assert.equal(c._compare(base, { status: 200, body: 'A'.repeat(1500) }), false);
  // 状态码不同 → 偏离
  assert.equal(c._compare(base, { status: 500, body: 'A'.repeat(1000) }), false);
});

test('基线懒抓取：首次探测前自动抓基线，后续比对稳定不告警', async () => {
  const inner = makeInner({ safeBody: 'SAME', safeStatus: 200 });
  const probes = [];
  const c = new SafeProbeClient(inner, {
    safeUrl: 'http://safe/',
    safeFreq: 2,
    onProbe: (p) => probes.push(p),
    onAnomaly: () => {},
  });
  assert.equal(c.baselines.size, 0);
  for (let i = 0; i < 6; i++) await c.request({ url: `http://real/?q=${i}` });
  // 第 1 次探测抓基线（baseline:true），第 2、3 次探测比对稳定
  const baselineProbe = probes.find((p) => p.baseline);
  assert.ok(baselineProbe, '基线应被抓取');
  assert.equal(c.baselines.get('http://safe/')?.body, 'SAME');
});

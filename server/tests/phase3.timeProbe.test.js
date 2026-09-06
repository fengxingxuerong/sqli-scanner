// P2-P8 time 盲注探测/提取 sleep 参数化分离测试（node --test）
// 验证：1) TimeBlindDetector 探测阶段优先用 timeProbeSleepSec（较短时长压低检测墙钟）；
//       2) 未配置 timeProbeSleepSec 时回退 timeBlindSleepSec（与现状一致，零回归）；
//       3) Extractor.extractTime 提取阶段优先用 timeExtractSleepSec（标准时长保证阈值可靠）；
//       4) 未配置 timeExtractSleepSec 时回退 timeBlindSleepSec。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { Extractor } from '../src/engine/Extractor.js';

// 捕获的原始 URL 中括号被 percent-encode，匹配前解码
const hasSleep = (u, sec) => /SLEEP\(\d+\)/.test(decodeURIComponent(u)) && decodeURIComponent(u).includes(`SLEEP(${sec})`);

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: {
      timeoutMs: 10000,
      retry: 0,
      timeThresholdMs: 800,
      blindRobust: { enabled: true, baselineSamples: 2, booleanSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 2 },
    },
    ...overrides,
  };
}

test('TimeBlindDetector：探测阶段优先 timeProbeSleepSec（timeBlindSleepSec=2 时用 1s）', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push(opts.url || '');
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 800, timeProbeSleepSec: 1, timeBlindSleepSec: 2, blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5 } },
  });
  const d = new TimeBlindDetector();
  await d.detect(ctx);
  assert.ok(captured.some((u) => hasSleep(u, 1)), `应使用 SLEEP(1)，实际请求=${captured.join(' | ')}`);
  assert.ok(!captured.some((u) => hasSleep(u, 2)), 'timeProbeSleepSec 生效时不应再使用 timeBlindSleepSec 时长');
});

test('TimeBlindDetector：未配置 timeProbeSleepSec 回退 timeBlindSleepSec', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push(opts.url || '');
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 800, timeBlindSleepSec: 2, blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5 } },
  });
  const d = new TimeBlindDetector();
  await d.detect(ctx);
  assert.ok(captured.some((u) => hasSleep(u, 2)), `未配置探测 sleep 应回退 timeBlindSleepSec=2，实际=${captured.join(' | ')}`);
});

test('Extractor.extractTime：提取阶段优先 timeExtractSleepSec 并放宽超时', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push({ url: opts.url || '', timeoutMs: opts.timeoutMs });
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, retry: 0, timeThresholdMs: 800, timeExtractSleepSec: 3, timeBlindSleepSec: 2 },
  });
  const ex = new Extractor();
  // mock 不延迟 → 时间判定恒 false → 长度二分返回 null，但探测请求已带 SLEEP(3) 与放宽超时
  const out = await ex.extractTime(ctx, 'version()');
  assert.equal(out, null);
  assert.ok(captured.length > 0, 'extractTime 应发起探测请求');
  // [B4 基线阈值修复] 提取前先发 2 次基线采样请求（无注入、无 SLEEP）；注入探测须全带 SLEEP(3)
  const probes = captured.filter((c) => hasSleep(c.url, 3));
  assert.ok(probes.length > 0, `注入探测应使用 SLEEP(3)，实际=${captured.map((c) => c.url).join(' | ')}`);
  assert.ok(probes.every((c) => c.timeoutMs >= 5000 + 3000), `探测超时应按提取 sleep 放宽（≥8000ms），实际=${probes[0]?.timeoutMs}`);
});

test('Extractor.extractTime：未配置 timeExtractSleepSec 回退 timeBlindSleepSec', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push({ url: opts.url || '', timeoutMs: opts.timeoutMs });
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, retry: 0, timeThresholdMs: 800, timeBlindSleepSec: 2 },
  });
  const ex = new Extractor();
  const out = await ex.extractTime(ctx, 'version()');
  assert.equal(out, null);
  // [B4 基线阈值修复] 基线采样请求无 SLEEP 属预期；注入探测请求须全带回退后的 SLEEP(2)
  const probes = captured.filter((c) => hasSleep(c.url, 2));
  assert.ok(probes.length > 0, `未配置提取 sleep 应回退 timeBlindSleepSec=2，实际=${captured.map((c) => c.url).join(' | ')}`);
});

// [主代理收尾] timeBlindSamples 配置透传生效测试（修复此前 _robustDetect/legacy 硬读 defaults
// 导致 REST 透传的 timeBlindSamples 不生效的配置语义漂移）
test('TimeBlindDetector：注入采样数读 config.timeBlindSamples（透传生效）', async () => {
  const run = async (timeBlindSamples) => {
    const captured = [];
    const httpClient = {
      async request(opts) {
        captured.push(opts.url || '');
        return { data: 'page', status: 200, headers: {} };
      },
    };
    const ctx = buildCtx(httpClient, {
      config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 800, timeBlindSleepSec: 1, timeBlindSamples, blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 2 } },
    });
    await new TimeBlindDetector().detect(ctx);
    return captured.filter((u) => /SLEEP\(\d+\)/.test(decodeURIComponent(u))).length;
  };
  // 鲁棒分支：注入采样数 = timeBlindSamples（基线 2 条不含 SLEEP 不计入）
  assert.equal(await run(3), 3, 'timeBlindSamples=3 → 注入采样应发 3 次');
  assert.equal(await run(1), 1, 'timeBlindSamples=1 → 注入采样应发 1 次');
  // clamp 上界 10（防直连引擎传病态值；REST 白名单区间 3-10）
  assert.equal(await run(99), 10, 'timeBlindSamples=99 → 应 clamp 到 10');
});

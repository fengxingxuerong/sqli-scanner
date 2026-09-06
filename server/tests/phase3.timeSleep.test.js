// P2-P5 time 盲注 sleep 参数化（timeBlindSleepSec）测试（node --test）
// 验证：1) TimeBlindDetector 检测阶段使用 config.timeBlindSleepSec（默认 2）拼进 payload；
//       2) Extractor.extractTime 提取阶段同样读取该配置并据此放宽超时。
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

test('TimeBlindDetector：检测阶段用 config.timeBlindSleepSec 拼 SLEEP 时长', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push(opts.url || '');
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, { config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 800, timeBlindSleepSec: 1, blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5 } } });
  const d = new TimeBlindDetector();
  await d.detect(ctx);
  assert.ok(captured.some((u) => hasSleep(u, 1)), `应使用 SLEEP(1)，实际请求=${captured.join(' | ')}`);
  assert.ok(!captured.some((u) => hasSleep(u, 2)), '不应使用默认 2s 之外的固定时长');
});

test('TimeBlindDetector：默认未配置时回退 defaults.timeBlindSleepSec=2', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push(opts.url || '');
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient);
  const d = new TimeBlindDetector();
  await d.detect(ctx);
  assert.ok(captured.some((u) => hasSleep(u, 2)), `默认应使用 SLEEP(2)，实际请求=${captured.join(' | ')}`);
});

test('Extractor.extractTime：提取阶段读取 timeBlindSleepSec 并放宽超时', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      captured.push({ url: opts.url || '', timeoutMs: opts.timeoutMs });
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = buildCtx(httpClient, {
    config: { timeoutMs: 5000, retry: 0, timeThresholdMs: 800, timeBlindSleepSec: 3 },
  });
  const ex = new Extractor();
  // mock 不延迟 → 时间判定恒 false → 长度二分返回 null，但探测请求已带 SLEEP(3) 与放宽超时
  const out = await ex.extractTime(ctx, 'version()');
  assert.equal(out, null);
  assert.ok(captured.length > 0, 'extractTime 应发起探测请求');
  // [B4 基线阈值修复] 提取前先发 2 次基线采样请求（无注入、无 SLEEP）；
  // 注入探测请求必须全部带 SLEEP(3) 且超时按 sleep 放宽（基线请求走默认超时，属预期）。
  const probes = captured.filter((c) => hasSleep(c.url, 3));
  assert.ok(probes.length > 0, `注入探测应使用 SLEEP(3)，实际=${captured.map((c) => c.url).join(' | ')}`);
  assert.ok(
    captured.every((c) => hasSleep(c.url, 3) || !/SLEEP\(/.test(decodeURIComponent(c.url))),
    `除基线采样外不应出现其他 SLEEP 时长，实际=${captured.map((c) => c.url).join(' | ')}`
  );
  assert.ok(probes.every((c) => c.timeoutMs >= 5000 + 3000), `探测超时应按 sleep 放宽（≥8000ms），实际=${probes[0]?.timeoutMs}`);
});

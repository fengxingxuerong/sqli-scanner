// ============================================================================
// tests/timeBlind.baselineFilter.test.js —— 时间盲注基线失败样本过滤（2026-10-01）
// ============================================================================
// 缺陷：_robustDetect 的基线统计把失败样本一并计入 —— 失败项的 __elapsed 是失败
// 本身的耗时：超时失败 ≈ timeoutMs（虚高 μ → 阈值飙天 → 稳定延迟的注入样本反而
// 够不到阈值 → 漏报）；快速失败（拒连）≈0（压低 μ → 阈值贴地 → 误报）。
// 注入侧循环早有 `!r.__error && r.resp != null` 护栏，基线侧没有。
// 本用例：2 个基线样本中第 2 个模拟「1.2s 后超时失败」——
//   旧行为：μ=(0.1+1.2)/2=0.65 → 阈值 ≥0.65+0.8=1.45 → 注入 1.1s 恒判未延迟 → 漏报；
//   新行为：μ=0.1（只看成功样本）→ 阈值=0.9 → 注入 1.1s 判延迟 → 检出。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';

test('TimeBlindDetector：超时失败的基线样本不得参与 μ/σ（否则阈值虚高 → 漏报）', async () => {
  let baselineCount = 0;
  const httpClient = {
    async request(opts) {
      const url = decodeURIComponent(opts.url || '');
      if (/SLEEP\(/.test(url)) {
        // 注入请求：目标真实执行 sleep（稳定延迟 1.1s）
        await new Promise((r) => setTimeout(r, 1100));
        return { data: 'page', status: 200, headers: {} };
      }
      baselineCount++;
      if (baselineCount === 2) {
        // 第二个基线样本：1.2s 后超时失败（__error + 大 __elapsed）
        await new Promise((r) => setTimeout(r, 1200));
        throw new Error('timeout exceeded');
      }
      // 正常基线：网络耗时 100ms
      return { data: 'page', status: 200, headers: {}, __networkMs: 100 };
    },
  };
  const ctx = {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      retry: 0,
      timeThresholdMs: 800, // absFloor=0.8s
      timeBlindSamples: 2,
      blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 2 },
    },
  };
  const r = await new TimeBlindDetector().detect(ctx);
  assert.ok(r.vulnerable, `失败基线样本抬高阈值导致稳定延迟目标漏报：${r.evidence || '(无证据)'}`);
});

test('TimeBlindDetector：基线全失败时回退固定阈值（μ=0/σ=0），不崩、不恒真', async () => {
  const httpClient = {
    async request(opts) {
      const url = decodeURIComponent(opts.url || '');
      if (/SLEEP\(/.test(url)) return { data: 'page', status: 200, headers: {}, __networkMs: 50 };
      throw new Error('connection refused'); // 基线全部快速失败
    },
  };
  const ctx = {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      retry: 0,
      timeThresholdMs: 800,
      timeBlindSamples: 2,
      blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 2 },
    },
  };
  const r = await new TimeBlindDetector().detect(ctx);
  assert.equal(r.vulnerable, false, '基线全失败 + 注入无延迟不得误判命中');
  assert.ok(Number.isFinite(r.trace.mu) && Number.isFinite(r.trace.threshold), 'μ/阈值必须为有限数');
});

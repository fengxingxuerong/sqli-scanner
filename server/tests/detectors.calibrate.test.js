// [--time-sec 自适应] TimeBlindDetector._robustDetect 时间盲注标定测试（node --test）
// 验证 timeBlindCalibrate=true 时：
//   1) 命中：SLEEP(min) 探针耗时 ≥ timeThresholdMs → 完整采样用短 sleep（降低单点墙钟）；
//   2) 未命中：探针耗时 < 阈值 → 回退原 sleep 做完整采样；
//   3) 默认关闭（legacy）零回归：不发 1s 探针，直接按原 sleep 采样。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 捕获请求并解码：SLEEP(1)/SLEEP(2) 命中时按配置延时（对标真实目标 sleep 生效），其余请求走 base 延时
function makeCalibrateMock({ one = 0, two = 0, base = 0 } = {}) {
  const captured = [];
  return {
    captured,
    async request(opts) {
      const q = decodeURIComponent(typeof opts.url === 'string' ? opts.url : '');
      captured.push(q);
      if (/SLEEP\(1\)/.test(q)) await sleep(one);
      else if (/SLEEP\(2\)/.test(q)) await sleep(two);
      else await sleep(base);
      return { data: 'page', status: 200, headers: {} };
    },
  };
}

const hasSleep = (u, sec) => /SLEEP\(\d+\)/.test(u) && u.includes(`SLEEP(${sec})`);

// 固定走 _robustDetect 分支（blindRobust.enabled=true）+ 稳定采样：并行 3 采样，基线 2 条
function buildCtx(httpClient, calibConfig) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      retry: 0,
      timeThresholdMs: 800,
      timeBlindSamples: 3,
      timeBlindSleepSec: 2,
      blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 3 },
      ...calibConfig,
    },
  };
}

test('timeBlindCalibrate 命中：SLEEP(1) 探针 ≥ 阈值 → 完整采样全部用 SLEEP(1)', async () => {
  const mock = makeCalibrateMock({ one: 1200, two: 2400 });
  const ctx = buildCtx(mock, { timeBlindCalibrate: true, timeBlindCalibrateMin: 1 });
  const res = await new TimeBlindDetector().detect(ctx);
  assert.equal(res.vulnerable, true, '探针命中且短 sleep 采样仍应确认注入');
  const sleepReqs = mock.captured.filter((u) => /SLEEP\(\d+\)/.test(u));
  assert.ok(sleepReqs.length > 0, '应发出 SLEEP 请求');
  // 所有 SLEEP 值均为 1（1 次探针 + timeBlindSamples 次采样），无 SLEEP(2)
  assert.ok(sleepReqs.every((u) => hasSleep(u, 1)), `所有 SLEEP 应为 1，实际=${sleepReqs.join(' | ')}`);
  assert.ok(!sleepReqs.some((u) => hasSleep(u, 2)), '命中后不应出现 SLEEP(2)');
  assert.equal(sleepReqs.filter((u) => hasSleep(u, 1)).length, 1 + 3, '应为 1 次探针 + 3 次采样');
});

test('timeBlindCalibrate 未命中：SLEEP(1) 探针 < 阈值 → 回退 SLEEP(2) 完整采样', async () => {
  const mock = makeCalibrateMock({ one: 500, two: 1600 });
  const ctx = buildCtx(mock, { timeBlindCalibrate: true, timeBlindCalibrateMin: 1 });
  const res = await new TimeBlindDetector().detect(ctx);
  assert.equal(res.vulnerable, true, '探针未命中回退 SLEEP(2) 采样仍应确认注入');
  const sleepReqs = mock.captured.filter((u) => /SLEEP\(\d+\)/.test(u));
  // 恰好 1 次 SLEEP(1) 探针（失败后未复用），完整采样 3 次全部 SLEEP(2)
  assert.equal(sleepReqs.filter((u) => hasSleep(u, 1)).length, 1, `探针应恰好 1 次 SLEEP(1)，实际=${sleepReqs.join(' | ')}`);
  assert.equal(sleepReqs.filter((u) => hasSleep(u, 2)).length, 3, '完整采样应全部回退 SLEEP(2)');
});

test('timeBlindCalibrate 默认关闭（legacy 零回归）：直接 SLEEP(2)，不发 1s 探针', async () => {
  const mock = makeCalibrateMock({ one: 1200, two: 1600 });
  const ctx = buildCtx(mock, {});
  const res = await new TimeBlindDetector().detect(ctx);
  const sleepReqs = mock.captured.filter((u) => /SLEEP\(\d+\)/.test(u));
  assert.ok(sleepReqs.every((u) => hasSleep(u, 2)), `关闭标定应直接 SLEEP(2)，实际=${sleepReqs.join(' | ')}`);
  assert.ok(!sleepReqs.some((u) => hasSleep(u, 1)), '关闭标定不应发 1s 探针');
  assert.equal(sleepReqs.length, 3, '采样数应为 timeBlindSamples，无额外探针');
  assert.equal(res.vulnerable, true, 'SLEEP(2) 生效仍应确认注入（回归语义不变）');
});
// ── [2026-09-24] 慢站回归：标定探针必须与「本次检测真正用的阈值」同量纲 ──────────
// 原实现的判据是 `elapsed >= (cfg.timeThresholdMs || 5000)`，比的是**绝对耗时 vs 增量下限**，
// 把页面自身的基线 μ 白送给了探针。上面两支既有测试的 base 都是 0（μ=0），
// 两种算法恰好给出同一个答案 —— 所以这个缺陷在既有测试里**永远照不出来**。
// 本支把 base 抬到 1.2s：判定阈值随之变成 μ+absFloor ≈ 2.0s；探针（SLEEP(1)）实测 1.5s ——
// 它已经**超过 absFloor(0.8s)**，所以旧判据据此认定"标定成功"并把 sleep 缩到 1s，
// 但 1.5s 从未越过真正要用的 2.0s。 旧规则会误判"标定成功"、把 sleep 缩到 1s，之后每次采样都停在
// 1.5s < 2.0s 上恒判未延迟 ⇒ 时间通道在这个点上必然漏报（且只在开了标定的慢站上漏，
// 正是这个开关服务的那类目标）。defaults.js 对本开关的说明写的就是"能否稳定超过**判定阈值**"。
test('timeBlindCalibrate 慢站（base 1.2s）：探针未越过真实阈值 → 不得缩短 sleep', async () => {
  const mock = makeCalibrateMock({ base: 1200, one: 1500, two: 2500 });
  const ctx = buildCtx(mock, { timeBlindCalibrate: true, timeBlindCalibrateMin: 1 });
  const res = await new TimeBlindDetector().detect(ctx);
  const sleepReqs = mock.captured.filter((u) => /SLEEP\(\d+\)/.test(u));
  assert.equal(res.vulnerable, true, 'SLEEP(2) 采样（2.5s ≥ 真实阈值 2.0s）应确认注入；若被误标定成 SLEEP(1)（1.5s）则恒判未延迟');
  assert.equal(sleepReqs.filter((u) => hasSleep(u, 1)).length, 1, `1s 只应出现在那一次探针里，实际=${sleepReqs.join(' | ')}`);
  assert.equal(sleepReqs.filter((u) => hasSleep(u, 2)).length, 3, '完整采样必须回退 SLEEP(2)');
});

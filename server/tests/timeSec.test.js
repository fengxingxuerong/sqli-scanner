// --time-sec（对标 sqlmap --time-sec）参数透传与阈值自适应单测
// 验证：默认 sleep=2 / 派生绝对下限 / 低 time-sec 不假阴性 / 越界 clamp / helper 边界
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';

// 从请求中取出注入值（与 detectors.test.js 同款提取逻辑）
function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  if (opts.headers && opts.headers.Cookie) {
    const m = opts.headers.Cookie.match(/q=([^;]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.headers) {
    for (const [k, v] of Object.entries(opts.headers)) {
      if (k.toLowerCase() !== 'cookie' && typeof v === 'string') return v;
    }
  }
  return '';
}

// mock：按 payload 中 SLEEP(N) 解析触发秒数，延迟 = N*1000ms，
// 保证"触发延迟严格等于用户设定的 SLEEP"，用于区分"延迟是否够大"与"判定门槛是否自适应"。
function makeTimeMock() {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      const m = q.match(/SLEEP\((\d+)\)|pg_sleep\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'/i);
      if (m) {
        const n = Number(m[1] || m[2] || m[3] || 2);
        await new Promise((r) => setTimeout(r, n * 1000));
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 8000, blindRobust: { enabled: false } }, // legacy 分支，聚焦阈值下限
    ...overrides,
  };
}

test('_absFloorFor: 默认 sleep=2 → 1.5s（与改造前 timeThresholdMs=1500 一致）', () => {
  const d = new TimeBlindDetector();
  assert.equal(d._absFloorFor(2), 1.5);
});

test('_absFloorFor: 低 sleep 兜底 0.3s（sleep<0.8 时下限不应为负）', () => {
  const d = new TimeBlindDetector();
  assert.ok(Math.abs(d._absFloorFor(1) - 0.5) < 1e-9);
  assert.ok(Math.abs(d._absFloorFor(0.8) - 0.3) < 1e-9);
  assert.ok(Math.abs(d._absFloorFor(0.5) - 0.3) < 1e-9);
});

test('_sleepFor: 默认 2s；显式 timeSec 生效；越界 clamp 到 [1,100]', () => {
  const d = new TimeBlindDetector();
  assert.equal(d._sleepFor({ config: {} }), 2);
  assert.equal(d._sleepFor({ config: { timeSec: 1 } }), 1);
  assert.equal(d._sleepFor({ config: { timeSec: 5 } }), 5);
  assert.equal(d._sleepFor({ config: { timeSec: 500 } }), 100); // 上限钳制
  assert.equal(d._sleepFor({ config: { timeSec: 0 } }), 2); // 低于下限→默认
  assert.equal(d._sleepFor({ config: { timeSec: -3 } }), 2);
});

test('默认 sleep=2：注入 2s 延迟 → 命中（下限 1.5s < 2s）', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(buildCtx(makeTimeMock()));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'time');
  assert.ok(res.evidence.includes('时间盲注'));
});

test('--time-sec=1：派生下限 0.5s，注入 1s 延迟仍能命中（关键：不假阴性）', async () => {
  const d = new TimeBlindDetector();
  // 若阈值仍固定为 1.5s（旧逻辑），1s 延迟会被判为"未延迟"→ 假阴性。
  const res = await d.detect(buildCtx(makeTimeMock(), { config: { timeoutMs: 8000, blindRobust: { enabled: false }, timeSec: 1 } }));
  assert.equal(res.vulnerable, true, 'time-sec=1 时 1s 延迟必须命中，证明阈值随 sleep 自适应');
});

test('--time-sec=1：0.3s 微延迟仍不命中（下限 0.5s 提供保护，不误报）', async () => {
  const d = new TimeBlindDetector();
  // 构造一个始终只延迟 0.3s 的 mock，验证下限保护生效
  const micro = {
    async request(opts) {
      if (/SLEEP\(|pg_sleep|WAITFOR DELAY/i.test(extractInjected(opts))) {
        await new Promise((r) => setTimeout(r, 300));
      }
      return { data: '', status: 200 };
    },
  };
  const res = await d.detect(buildCtx(micro, { config: { timeoutMs: 8000, blindRobust: { enabled: false }, timeSec: 1 } }));
  assert.equal(res.vulnerable, false, '0.3s 微延迟应判为干净（低于 0.5s 下限）');
});

test('--time-sec 经 robust 分支同样生效（统计判定路径）', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(buildCtx(makeTimeMock(), {
    config: {
      timeoutMs: 8000,
      blindRobust: { enabled: true, baselineSamples: 3, timeConfidenceZ: 2, minStableRatio: 0.66, adaptive: true, adaptiveTimeFloorScale: 2, concurrency: 4 },
      timeSec: 1,
    },
  }));
  assert.equal(res.vulnerable, true, 'robust 分支也应随 timeSec=1 自适应下限并命中 1s 延迟');
});

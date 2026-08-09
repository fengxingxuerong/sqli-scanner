// 检测器单元测试：Error/Boolean/Time/Union
// 通过 mock httpClient 模拟易受攻击目标行为，验证各检测器真实生效。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';

// 从请求中取出注入值（注入值放在 url query / body / cookie / header）
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

// mode: 'error' | 'boolean' | 'union' | 'time'
function makeDetectorMock(mode) {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (mode === 'error') {
        if (/extractvalue|updatexml|SLEEP|pg_sleep|WAITFOR/i.test(q)) {
          return { data: 'You have an error in your SQL syntax near ...', status: 200 };
        }
        return { data: `normal page for ${q}`, status: 200 };
      }
      if (mode === 'boolean') {
        // 真条件（1=1）返回与原始页面相同的正常结果；假条件（1=2）返回空结果。
        // 模拟真实注入：AND 1=1 不改变结果集，故响应≈原始页面（基线）。
        if (/1=2|'1'='2|"1"="2/.test(q)) return { data: 'NO_RESULTS', status: 200 };
        return { data: 'normal', status: 200 };
      }
      if (mode === 'union') {
        if (/ORDER BY/i.test(q)) return { data: 'ERR', status: 200 };
        return { data: `echo:${q}`, status: 200 };
      }
      if (mode === 'time') {
        // 默认 sleep=2 → 绝对下限 1.5s；延迟需 > 1.5s 才能触发命中（与改造后一致）。
        if (/SLEEP\(|pg_sleep|WAITFOR DELAY/i.test(q)) {
          await new Promise((r) => setTimeout(r, 2000));
        }
        return { data: '', status: 200 };
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
    config: { timeoutMs: 5000, timeThresholdMs: 800 },
    ...overrides,
  };
}

// ===== ErrorDetector =====
test('ErrorDetector 命中报错特征', async () => {
  const d = new ErrorDetector();
  const res = await d.detect(buildCtx(makeDetectorMock('error'), { dbms: 'MySQL' }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'error');
  assert.ok(res.evidence.includes('报错'));
});

test('ErrorDetector dbms=null 仍遍历全部库报错 payload 可命中', async () => {
  const d = new ErrorDetector();
  const res = await d.detect(buildCtx(makeDetectorMock('error'), { dbms: null }));
  assert.equal(res.vulnerable, true);
});

test('ErrorDetector 无报错特征时不误报', async () => {
  const noErr = { async request() { return { data: 'all good', status: 200 }; } };
  const d = new ErrorDetector();
  const res = await d.detect(buildCtx(noErr, { dbms: 'MySQL' }));
  assert.equal(res.vulnerable, false);
});

// ===== BooleanBlindDetector =====
test('BooleanBlindDetector 命中布尔差异', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeDetectorMock('boolean')));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
});

test('BooleanBlindDetector 仅空白差异时不误报（_isMeaningfulDiff）', async () => {
  const wsOnly = {
    async request(opts) {
      const q = extractInjected(opts);
      return { data: q.includes('1=2') ? 'same ' : 'same', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(wsOnly));
  assert.equal(res.vulnerable, false);
});

test('BooleanBlindDetector 真/假响应完全相同时不误报', async () => {
  const same = { async request() { return { data: 'identical', status: 200 }; } };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(same));
  assert.equal(res.vulnerable, false);
});

// ===== TimeBlindDetector =====
test('TimeBlindDetector 命中时间延迟', async () => {
  const d = new TimeBlindDetector();
  const res = await d.detect(
    buildCtx(makeDetectorMock('time'), { config: { timeoutMs: 5000, timeThresholdMs: 800 } })
  );
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'time');
  assert.ok(res.evidence.includes('时间盲注'));
});

test('TimeBlindDetector 无延迟时不误报', async () => {
  const fast = { async request() { return { data: '', status: 200 }; } };
  const d = new TimeBlindDetector();
  const res = await d.detect(
    buildCtx(fast, { config: { timeoutMs: 5000, timeThresholdMs: 800 } })
  );
  assert.equal(res.vulnerable, false);
});

// ===== UnionDetector =====
test('UnionDetector 命中 UNION 回显', async () => {
  const d = new UnionDetector();
  const res = await d.detect(buildCtx(makeDetectorMock('union')));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'union');
  assert.ok(res.evidence.includes('UNION'));
});

test('UnionDetector 无可回显时不误报', async () => {
  const noEcho = {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { data: 'ERR', status: 200 };
      return { data: 'no marker here', status: 200 };
    },
  };
  const d = new UnionDetector();
  const res = await d.detect(buildCtx(noEcho));
  assert.equal(res.vulnerable, false);
});

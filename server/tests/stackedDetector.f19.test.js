// StackedDetector 真实命中验证（F-19）：以 `;` 追加 SLEEP 触发时间延迟，
// 验证检测器在 MySQL/PostgreSQL/SQL Server 上真实命中，Oracle 不投放，无延迟不误报。
// 风格对齐 detectors.test.js（mock httpClient 模拟靶机）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { StackedDetector } from '../src/engine/detectors/StackedDetector.js';

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

// mode: 'stacked' 仅在 `;` 后带延迟函数时触发延迟
function makeStackedMock() {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      // 堆叠特征：`;` 后（可含 SELECT）追加 SLEEP/pg_sleep/WAITFOR
      if (/;\s*(SELECT\s+)?(SLEEP\(|pg_sleep|WAITFOR DELAY)/i.test(q)) {
        await new Promise((r) => setTimeout(r, 1200));
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

test('StackedDetector MySQL 命中（`;` SLEEP 延迟）', async () => {
  const d = new StackedDetector();
  const res = await d.detect(buildCtx(makeStackedMock(), { dbms: 'MySQL' }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'stacked');
  assert.ok(res.evidence.includes('第二条语句'));
});

test('StackedDetector PostgreSQL 命中（`;` pg_sleep 延迟）', async () => {
  const d = new StackedDetector();
  const res = await d.detect(buildCtx(makeStackedMock(), { dbms: 'PostgreSQL' }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'stacked');
});

test('StackedDetector SQL Server 命中（`;` WAITFOR 延迟）', async () => {
  const d = new StackedDetector();
  const res = await d.detect(buildCtx(makeStackedMock(), { dbms: 'SQL Server' }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'stacked');
});

test('StackedDetector Oracle 不投放（直接未命中）', async () => {
  const d = new StackedDetector();
  const res = await d.detect(buildCtx(makeStackedMock(), { dbms: 'Oracle' }));
  assert.equal(res.vulnerable, false);
  assert.ok(res.evidence.includes('Oracle'));
});

test('StackedDetector 无延迟时不误报', async () => {
  const fast = { async request() { return { data: '', status: 200 }; } };
  const d = new StackedDetector();
  const res = await d.detect(buildCtx(fast, { dbms: 'MySQL' }));
  assert.equal(res.vulnerable, false);
});

// 盲注响应匹配多指标判定增强测试（node --test）
// 覆盖：matchText（纯文本差异）/ matchCode（状态码差异）/ matchRegexp（正则命中）/
//       matchTitle（标题差异）/ autoDynamicBlock（动态块排除）/ 默认关闭行为不变（回归）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

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

function buildCtx(httpClient, configOverrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: {
      timeoutMs: 5000,
      timeThresholdMs: 800,
      blindRobust: { enabled: true, booleanSamples: 3, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66 },
      ...configOverrides,
    },
  };
}

// 布尔真假判定统一正则（与既有检测器测试一致）
const IS_FALSE = /1=2|'1'='2|"1"="2/;

// ===== T1：matchText（--text-only）=====
test('matchText：剥标签后纯文本不一致即信号', () => {
  const d = new Detector('boolean');
  const t = '<html><body><div>Welcome back</div><span id="ts">123</span></body></html>';
  const f = '<html><body><div>No results found</div><span id="ts">456</span></body></html>';
  assert.equal(d.matchText(t, f, { matchText: true }), true);
});

test('matchText：纯文本一致不误报（动态内容在标签属性内被剥离）', () => {
  const d = new Detector('boolean');
  const a = '<html><body><div data-ts="111">Same text</div></body></html>';
  const b = '<html><body><div data-ts="222">Same text</div></body></html>';
  assert.equal(d.matchText(a, b, { matchText: true }), false);
});

test('matchText：未配置返回 null（回落默认路径）', () => {
  const d = new Detector('boolean');
  assert.equal(d.matchText('a', 'b', {}), null);
  assert.equal(d.matchText('a', 'b', { matchText: false }), null);
});

// ===== T1：matchCode（--code）=====
test('_matchByCode：状态码不同即弱信号（matchCode=true）', () => {
  const d = new Detector('boolean');
  assert.equal(d._matchByCode({ status: 200 }, { status: 500 }, { matchCode: true }), true);
  assert.equal(d._matchByCode({ status: 200 }, { status: 200 }, { matchCode: true }), false);
});

test('_matchByCode：指定期望状态码精确匹配（{true,false}）', () => {
  const d = new Detector('boolean');
  assert.equal(d._matchByCode({ status: 200 }, { status: 500 }, { matchCode: { true: 200, false: 500 } }), true);
  assert.equal(d._matchByCode({ status: 200 }, { status: 200 }, { matchCode: { true: 200, false: 500 } }), false);
  assert.equal(d._matchByCode({ status: 200 }, { status: 500 }, {}), null);
});

// ===== T1：matchRegexp（--regexp）=====
test('_matchByRegexp：真命中假不命中即信号', () => {
  const d = new Detector('boolean');
  assert.equal(d._matchByRegexp('page with ADMIN_PANEL', 'normal page', { matchRegexp: 'ADMIN_PANEL' }), true);
  assert.equal(d._matchByRegexp('normal page', 'normal page', { matchRegexp: 'ADMIN_PANEL' }), false);
});

test('_matchByRegexp：trueRegexp/falseRegexp 组合', () => {
  const d = new Detector('boolean');
  assert.equal(d._matchByRegexp('has OK', 'has ERR', { trueRegexp: 'OK', falseRegexp: 'ERR' }), true);
  assert.equal(d._matchByRegexp('has OK', 'has ERR', { trueRegexp: 'NOPE' }), false);
  assert.equal(d._matchByRegexp('a', 'b', {}), null);
});

// ===== T1：matchTitle（--titles）=====
test('_matchByTitle：标题不同即信号', () => {
  const d = new Detector('boolean');
  assert.equal(d._matchByTitle('<title>Products</title>', '<title>Error</title>', { matchTitle: true }), true);
  assert.equal(d._matchByTitle('<title>Same</title>x', '<title>Same</title>y', { matchTitle: true }), false);
  assert.equal(d._matchByTitle('a', 'b', {}), null);
});

// ===== T1：matchMetrics 汇总 / hasExplicitMatch =====
test('matchMetrics：任一显式指标命中即 true、全无差异 false、全未配置 null', () => {
  const d = new Detector('boolean');
  assert.equal(d.matchMetrics({ data: 'x', status: 200 }, { data: 'y', status: 500 }, { matchCode: true }), true);
  assert.equal(d.matchMetrics({ data: 'a', status: 200 }, { data: 'a', status: 200 }, { matchCode: true }), false);
  assert.equal(d.matchMetrics({ data: 'a' }, { data: 'b' }, {}), null);
});

test('hasExplicitMatch：默认配置无显式指标 → false', () => {
  const d = new Detector('boolean');
  assert.equal(d.hasExplicitMatch(defaults), false);
  assert.equal(d.hasExplicitMatch({ matchText: true }), true);
  assert.equal(d.hasExplicitMatch({ matchCode: true }), true);
  assert.equal(d.hasExplicitMatch({ matchTitle: true }), true);
  assert.equal(d.hasExplicitMatch({ matchRegexp: 'x' }), true);
});

// ===== T2：autoDynamicBlock（动态块排除）=====
test('buildDynamicSimilar：识别基线动态块并排除', () => {
  const d = new Detector('boolean');
  const common = 'X'.repeat(64 * 4); // 4 个稳定块
  const b1 = 'T'.repeat(64) + common; // 首块为动态（时间戳）
  const b2 = 'U'.repeat(64) + common;
  const sim = d.buildDynamicSimilar([b1, b2], { autoDynamicBlock: true });
  assert.ok(typeof sim === 'function', '开启时返回排除动态块的相似判定函数');
  assert.equal(sim(b1, b2), true, '仅动态块不同应判相似');
  const c2 = 'T'.repeat(64) + 'Y'.repeat(64) + 'X'.repeat(64 * 3); // 稳定块不同
  assert.equal(sim(b1, c2), false, '稳定块不同应判不相似');
});

test('buildDynamicSimilar：默认关闭或无动态块返回 null', () => {
  const d = new Detector('boolean');
  assert.equal(d.buildDynamicSimilar(['a', 'b'], {}), null);
  assert.equal(d.buildDynamicSimilar(['same', 'same'], { autoDynamicBlock: true }), null);
});

// ===== 集成：BooleanBlindDetector 显式指标优先判定 =====
test('Boolean 集成：matchText 纯文本差异检出（HTML 动态内容场景）', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      const ts = Math.random().toString(36).slice(2, 10);
      if (IS_FALSE.test(q)) return { data: `<html><body><span id="ts">${ts}</span><p>No products found</p></body></html>`, status: 200 };
      return { data: `<html><body><span id="ts">${ts}</span><p>Product list here</p></body></html>`, status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock, { matchText: true }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
  assert.ok(res.evidence.includes('响应匹配多指标'));
});

test('Boolean 集成：matchCode 状态码差异检出', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      return { data: 'x', status: IS_FALSE.test(q) ? 500 : 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock, { matchCode: true }));
  assert.equal(res.vulnerable, true);
});

test('Boolean 集成：matchRegexp 正则命中检出', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      return { data: IS_FALSE.test(q) ? 'ACCESS DENIED' : 'WELCOME ADMIN', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock, { matchRegexp: 'WELCOME' }));
  assert.equal(res.vulnerable, true);
});

test('Boolean 集成：matchTitle 标题差异检出', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      return { data: IS_FALSE.test(q) ? '<title>No Results</title>' : '<title>Products</title>', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock, { matchTitle: true }));
  assert.equal(res.vulnerable, true);
});

test('Boolean 集成：autoDynamicBlock 排除基线动态块后仍检出（稳定块差异）', async () => {
  let n = 0;
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      const ts = String(n++).padStart(64, '0'); // 64 字符动态块（每次请求变化）
      const stable = IS_FALSE.test(q) ? 'NO_RESULTS'.padEnd(128, 'F') : 'PRODUCT_LIST'.padEnd(128, 'T');
      return { data: ts + stable, status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(
    buildCtx(mock, { autoDynamicBlock: true, blindRobust: { enabled: true, booleanSamples: 3, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66 } })
  );
  assert.equal(res.vulnerable, true, '排除动态块后，稳定块的真假差异应仍能检出');
});

// ===== 回归：默认未配置时行为不变（仍走盲注统计判定）=====
test('默认未配置响应匹配指标：Boolean 仍走统计判定（证据含「统计」）', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      return { data: IS_FALSE.test(q) ? 'NO_RESULTS' : 'normal page content here stable prefix', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock)); // 无任何显式匹配指标
  assert.equal(res.vulnerable, true);
  assert.ok(res.evidence.includes('统计'), '默认应走统计判定，而非响应匹配多指标');
});

test('默认未配置：Time 仍走时间延迟判定', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      if (/SLEEP\(|pg_sleep|WAITFOR DELAY/i.test(q)) await new Promise((r) => setTimeout(r, 1200));
      return { data: '', status: 200 };
    },
  };
  const d = new TimeBlindDetector();
  const res = await d.detect(
    buildCtx(mock, { timeThresholdMs: 800, blindRobust: { enabled: true, baselineSamples: 5, timeConfidenceZ: 2, minStableRatio: 0.66, booleanSamples: 3 } })
  );
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'time');
});

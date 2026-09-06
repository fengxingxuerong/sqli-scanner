// 检测器单元测试：Error/Boolean/Time/Union
// 通过 mock httpClient 模拟易受攻击目标行为，验证各检测器真实生效。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { Detector } from '../src/engine/Detector.js';

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
        // ★FIX-2 语义修正：模拟「真实 UNION 注入目标」而非「无条件反射目标」。
        // 真实注入点：AND 1=1 恒真（≈基线）、AND 1=2 恒假（空结果）、
        // ORDER BY 超出列数报错、UNION SELECT 标记落在回显列。
        // 无条件反射（echo:q）是参数反射症状，属安全目标，不应判 UNION 命中。
        if (/AND 1=2/.test(q) || /'1'='2/.test(q)) return { data: 'NO_RESULTS', status: 200 };
        if (/ORDER BY \d+/.test(q)) {
          const n = Number(q.match(/ORDER BY (\d+)/)[1]);
          return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
        }
        return { data: `echo:${q}`, status: 200 };
      }
      if (mode === 'time') {
        if (/SLEEP\(|pg_sleep|WAITFOR DELAY/i.test(q)) {
          await new Promise((r) => setTimeout(r, 1200));
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

// 回归：数字型注入点（无引号闭合）—— 仅 1=2（数字型假）产生差异，
// 引号型 '1'='2 / "1"="2 不触发 → 若检测器只用引号型 payload 将漏报。
// 验证补齐数字型闭合后，id=1 这类纯数字注入点能被检出。
test('BooleanBlindDetector 检出数字型注入点（无引号闭合）', async () => {
  const numericOnly = {
    async request(opts) {
      const q = extractInjected(opts);
      // 仅数字型 1=2 命中（引号型 '1'='2 的 1 与 = 被引号隔开，不匹配 \b1=2\b）
      if (/\b1=2\b/.test(q)) return { data: 'NO_RESULTS', status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(numericOnly, { dbms: 'MySQL' }));
  assert.equal(res.vulnerable, true, '数字型注入点应被检出（依赖数字型闭合 payload）');
  assert.equal(res.technique, 'boolean');
});

// ===== BooleanBlindDetector：OR-based 布尔对（risk>=2 门控，对标 sqlmap --risk）=====
test('BooleanBlindDetector：risk>=2 时投放 OR-based 布尔对检出（[6,7]）', async () => {
  // 仅 OR-based 模式产生响应差异（AND 型真假无差异 → risk=1 时漏检）
  const orOnly = {
    async request(opts) {
      const q = extractInjected(opts);
      if (q.includes("OR '1'='2")) return { data: 'NO_RESULTS', status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const clean = await d.detect(buildCtx(orOnly, { config: { timeoutMs: 5000, risk: 1 } }));
  assert.equal(clean.vulnerable, false, 'risk=1 不投放 OR 对，应判干净');
  const hit = await d.detect(buildCtx(orOnly, { config: { timeoutMs: 5000, risk: 2 } }));
  assert.equal(hit.vulnerable, true, 'risk=2 应经 OR 对检出');
  assert.ok(hit.payloads.some((p) => p.includes("OR '1'='1")), `payload 应为 OR 变体: ${JSON.stringify(hit.payloads)}`);
});

test('BooleanBlindDetector：risk=2 时 AND 型目标仍正常检出（回归）', async () => {
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(makeDetectorMock('boolean'), { config: { timeoutMs: 5000, risk: 2 } }));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
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

// ===== Detector: 首请求自动学习页面特征（baseTitle）=====
test('probeBoundary 提取 <title> 存入 ctx.point._baselineTitle', async () => {
  const mock = {
    async request() {
      return {
        data: '<html><head><title>Test Page</title></head><body>ok</body></html>',
        status: 200,
      };
    },
  };
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false };
  const ctx = {
    httpClient: mock,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point,
    config: {},
  };
  const d = new Detector('test');
  await d.probeBoundary(ctx);
  assert.equal(point._baselineTitle, 'Test Page', '基线标题应被提取');
});

test('probeBoundary 无 <title> 时 _baselineTitle 为空串', async () => {
  const mock = {
    async request() {
      return { data: '<html><body>no title here</body></html>', status: 200 };
    },
  };
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false };
  const ctx = {
    httpClient: mock,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point,
    config: {},
  };
  const d = new Detector('test');
  await d.probeBoundary(ctx);
  assert.equal(point._baselineTitle, '', '无标题时 _baselineTitle 应为空串');
});

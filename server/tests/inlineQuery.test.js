// P2-A 内联查询（对标 sqlmap Q）检测回归
// 验证：①内联标记随响应回显 → 命中；②无回显点/标记已在基线 → 不误报；
//        ③ScanManager 默认 techniques 不含 inline → 不投；④techniques 含 inline → 命中。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InlineQueryDetector } from '../src/engine/detectors/InlineQueryDetector.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { INLINE_MARKER } from '../src/engine/detectors/InlineQueryDetector.js';

// 桩 httpClient：模拟"回显点"——当注入值含内联子查询标记时，把标记原样带回响应。
function extractValue(req) {
  const url = req.url || '';
  try {
    const u = new URL(url);
    const vals = [...u.searchParams.values()];
    if (vals.length) return vals[0];
  } catch {}
  if (req.params && Object.keys(req.params).length) return Object.values(req.params)[0];
  if (req.data && Object.keys(req.data).length) return Object.values(req.data)[0];
  return '';
}

function makeClient({ echoInline = false } = {}) {
  return {
    async request(req) {
      const body = String(extractValue(req) || '');
      // 模拟回显点：SQL 求值的子查询结果被带出响应（含内联标记）
      if (echoInline && body.includes(`SELECT '${INLINE_MARKER}'`)) {
        return { status: 200, headers: {}, data: `welcome __S__INL__E__ and more` };
      }
      return { status: 200, headers: {}, data: 'normal-page-no-marker' };
    },
  };
}

function makeCtx(httpClient, point = { id: 'p1', originalValue: '1', param: 'q', location: 'url', dbms: 'MySQL' }) {
  return { httpClient, target: { baseUrl: 'http://x/' }, point, config: {}, dbms: point.dbms };
}

test('P2-A: 内联子查询标记随响应回显 → 命中 inline', async () => {
  const d = new InlineQueryDetector();
  const r = await d.detect(makeCtx(makeClient({ echoInline: true })));
  assert.equal(r.vulnerable, true, '内联回显点应命中');
  assert.equal(r.technique, 'inline');
  assert.ok(r.payloads.length >= 1, '应记录内联 payload');
});

test('P2-A: 无回显点（标记不带回响应）→ 不误报', async () => {
  const d = new InlineQueryDetector();
  const r = await d.detect(makeCtx(makeClient({ echoInline: false })));
  assert.equal(r.vulnerable, false, '无回显点不应误报 inline');
});

test('P2-A: 标记本就存在于基线响应 → 不误报（排除页面固有标记）', async () => {
  const d = new InlineQueryDetector();
  // 基线已含标记（异常站点常驻该串）：测试也应含，但基线同样含 → 不满足"测试有而基线无"
  const client = {
    async request() {
      return { status: 200, headers: {}, data: `page always shows __S__INL__E__ tag` };
    },
  };
  const r = await d.detect(makeCtx(client));
  assert.equal(r.vulnerable, false, '基线已含标记不应误报');
});

test('P2-A: ScanManager 默认 techniques 不含 inline → 不投内联检测（对经典 SQLi 零侵入）', async () => {
  let inlineCalls = 0;
  const sm = new ScanManager();
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null, extractInlineProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'q', originalValue: '1' }]; } };
  sm.httpClient = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes(`SELECT '${INLINE_MARKER}'`)) inlineCalls++;
      return { status: 200, headers: {}, data: 'normal' };
    },
  };
  const id = await sm.start({ url: 'http://x/?q=1', config: { concurrency: 1, ratePerSec: 100 } });
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  const report = sm.getReport(id);
  assert.equal(inlineCalls, 0, '默认 techniques 不应发起内联检测');
  assert.ok(!report.vulns.some((v) => v.technique === 'inline'), '默认不应有 inline 命中');
});

test('P2-A: techniques 含 inline 且存在回显点 → inline 命中并入报告', async () => {
  const sm = new ScanManager();
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null, extractInlineProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'q', originalValue: '1' }]; } };
  sm.httpClient = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes(`SELECT '${INLINE_MARKER}'`)) {
        return { status: 200, headers: {}, data: `result __S__INL__E__ ok` };
      }
      return { status: 200, headers: {}, data: 'normal' };
    },
  };
  const id = await sm.start({
    url: 'http://x/?q=1',
    config: { concurrency: 1, ratePerSec: 100, techniques: ['union', 'error', 'boolean', 'time', 'inline'] },
  });
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  const report = sm.getReport(id);
  const inlineVuln = report.vulns.find((v) => v.technique === 'inline');
  assert.ok(inlineVuln, '开启 inline 且存在回显点应命中');
});

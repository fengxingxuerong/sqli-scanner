// P2-P8 CPU 比对下沉测试（node --test）
// 验证：1) _statusDiffer 状态码粗筛：真/假状态不同即视为有意义差异（跳过 body 精细比对）；
//       2) BooleanBlindDetector 状态码粗筛路径仍正确检出注入（真假状态不同）；
//       3) _isMeaningfulDiff 零分配流式比对语义与 replace 版本等价（仅空白差异不误报），大 body 也正确；
//       4) Detector.chunkedSimilar 大 body 首尾采样快速路径：命中直接判相似，不弱化动态首块的分块兜底。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, timeThresholdMs: 800 },
    ...overrides,
  };
}

// ===== 1) 状态码粗筛 =====
test('_statusDiffer：状态码不同快速判定不同，相同或缺失不短路', () => {
  const d = new BooleanBlindDetector();
  assert.equal(d._statusDiffer({ status: 200 }, { status: 500 }), true, '200 vs 500 应判不同');
  assert.equal(d._statusDiffer({ status: 200 }, { status: 200 }), false, '相同状态码不短路');
  assert.equal(d._statusDiffer({ status: 200 }, { data: 'x' }), false, '状态码缺失不应短路（回落 body 精细比对）');
  assert.equal(d._statusDiffer(null, { status: 500 }), false);
});

test('BooleanBlindDetector：真假状态码不同时状态码粗筛路径仍正确检出注入', async () => {
  // 真/基线返回 200 正常页，假条件返回 500 错误页 → 状态码粗筛直接判定有意义差异
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      const isFalse = /1=2|'1'='2|"1"="2/.test(q);
      return isFalse ? { data: 'ERROR PAGE', status: 500 } : { data: 'normal page stable', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock));
  assert.equal(res.vulnerable, true, '状态码不同的真假对应检出注入');
  assert.equal(res.technique, 'boolean');
});

// ===== 2) _isMeaningfulDiff 零分配等价性 =====
test('_isMeaningfulDiff：仅空白差异不误报（零分配流式比对语义与 replace 版本等价）', () => {
  const d = new BooleanBlindDetector();
  // 长度差 ≤1 的纯空白差异 → 不 meaningful
  assert.equal(d._isMeaningfulDiff('same ', 'same'), false, '尾随空白不应判有意义差异');
  assert.equal(d._isMeaningfulDiff('abc', ' abc'), false, '前导空白不应判有意义差异');
  assert.equal(d._isMeaningfulDiff('ab c', 'ab  c'), false, '中间空白差异不应判有意义差异');
  // 实质内容不同 → meaningful
  assert.equal(d._isMeaningfulDiff('abc', 'abx'), true, '内容不同应判有意义差异');
  assert.equal(d._isMeaningfulDiff('abc', 'abcd'), true, '长度差 1 + 内容不同应判有意义差异');
  assert.equal(d._isMeaningfulDiff('abcdef', 'abc'), true, '长度差 >1 应判有意义差异');
});

test('_isMeaningfulDiff：大 body 零分配路径结果正确（仅空白差异不误报）', () => {
  const d = new BooleanBlindDetector();
  const bigA = 'A'.repeat(200000) + ' ';
  const bigB = 'A'.repeat(200000);
  // 长度差 1 且仅差尾随空白 → 不 meaningful（流式比对无整串拷贝）
  assert.equal(d._isMeaningfulDiff(bigA, bigB), false);
  const bigC = 'A'.repeat(200000) + 'X';
  assert.equal(d._isMeaningfulDiff(bigB, bigC), true, '大 body 实质差异仍应判有意义');
});

// ===== 3) chunkedSimilar 大 body 快速路径 =====
test('chunkedSimilar：大 body 首尾采样命中直接判相似（省整串 LCP/分块 hash）', () => {
  const d = new Detector('boolean');
  const head = 'H'.repeat(300);
  const tail = 'Z'.repeat(300);
  // 同长度大 body（>64KB）：首尾 256 字符一致、中段不同 → 首尾采样快速判相似
  const a = head + 'A'.repeat(70000) + tail;
  const b = head + 'B'.repeat(70000) + tail;
  assert.ok(a.length > 65536, '应构造超过 64KB 的 body');
  assert.equal(d.chunkedSimilar(a, b), true, '大 body 首尾采样命中应判相似');
});

test('chunkedSimilar：大 body 首部动态块回落分块相似率兜底（不弱化 P1-D4）', () => {
  const d = new Detector('boolean');
  const common = 'M'.repeat(70000);
  const a = 'A'.repeat(256) + common;
  const b = 'B'.repeat(256) + common;
  assert.ok(a.length > 65536);
  assert.equal(d.chunkedSimilar(a, b), true, '首块动态（时间戳/CSRF）应经分块兜底判相似');
});

test('chunkedSimilar：大 body 完全无关或长度差超容差判不相似', () => {
  const d = new Detector('boolean');
  assert.equal(d.chunkedSimilar('A'.repeat(70000), 'B'.repeat(70000)), false, '大 body 完全无关应判不相似');
  assert.equal(d.chunkedSimilar('A'.repeat(70000), 'A'.repeat(80000)), false, '大 body 长度差超容差应判不相似');
});

test('chunkedSimilar：小 body 行为不变（零回归）', () => {
  const d = new Detector('boolean');
  const common = 'X'.repeat(64 * 8);
  const a = 'A'.repeat(64) + common;
  const b = 'B'.repeat(64) + common;
  assert.equal(d.chunkedSimilar(a, b), true, '首部动态内容分块兜底仍生效');
  assert.equal(d.chunkedSimilar('a'.repeat(500), 'b'.repeat(500)), false);
  assert.equal(d.chunkedSimilar('same', 'same'), true);
});

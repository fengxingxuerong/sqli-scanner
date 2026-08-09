// UNION 标记大小写不敏感匹配测试
//
// 背景（Bug 修复）：UnionDetector / discoverEchoColumns 向 UNION 注入确定性标记
// `SQLISCANNER<序号>` 以定位回显列。当 randomcase / charunicodeencode 等 tamper
// 作用于 payload 时，注入到响应体中的标记字母大小写会被随机化。原 `body.includes(标记)`
// 为大小写敏感匹配，会导致 UNION 检测漏报。
//
// 本测试用 mock httpClient 模拟「目标把回显标记大小写打乱」的真实场景，验证修复后
// 检测器仍能命中。若仍用大小写敏感匹配，则这些用例会失败（非空转）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { discoverEchoColumns } from '../src/engine/injection.js';

// 从请求中取出注入值（与 Detector.buildRequest 的 url 注入点一致：?q=<value>）
function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// 模拟 randomcase / charunicodeencode tamper 把回显标记 SQLISCANNER<数字> 的大小写打乱：
// 将标记中每个字母反转大小写（确定可复现，且与原始全大写标记不同）。
// 例：SQLISCANNER0 -> sQlIsCaNnEr0
function scrambleMarkerCase(s) {
  return s.replace(/SQLISCANNER(\d+)/gi, (m) =>
    m
      .split('')
      .map((c) => (c >= 'a' && c <= 'z' ? c.toUpperCase() : c.toLowerCase()))
      .join('')
  );
}

// 模拟易受 UNION 注入的目标：ORDER BY 报 ERR；其余把请求原样回显，
// 但其中 SQLISCANNER 标记的大小写被打乱（模拟 tamper 副作用）。
function makeCaseScrambledUnionMock() {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { data: 'ERR', status: 200 };
      return { data: `echo:${scrambleMarkerCase(q)}`, status: 200 };
    },
  };
}

// 无 tamper 的普通回显目标（对照组：标记大小写不变也应命中）。
function makePlainUnionMock() {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { data: 'ERR', status: 200 };
      return { data: `echo:${q}`, status: 200 };
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
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 4 },
    ...overrides,
  };
}

// ===== UnionDetector：标记大小写被打乱仍能命中（修复验证）=====
test('UnionDetector 回显标记大小写被打乱(randomcase) 仍能判定 UNION 注入', async () => {
  const d = new UnionDetector();
  const ctx = buildCtx(makeCaseScrambledUnionMock());
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'union');
  // 大小写不敏感匹配下应定位到全部回显列
  assert.deepEqual(ctx.point.echoCols, [0, 1, 2, 3]);
});

// ===== UnionDetector：对照组（无 tamper，标记大小写不变，不应回归）=====
test('UnionDetector 回显标记大小写不变时仍命中（零回归）', async () => {
  const d = new UnionDetector();
  const ctx = buildCtx(makePlainUnionMock());
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.deepEqual(ctx.point.echoCols, [0, 1, 2, 3]);
});

// ===== discoverEchoColumns（Extractor/DBFingerprinter 复用）：标记大小写打乱仍能定位 =====
test('discoverEchoColumns 回显标记大小写被打乱(randomcase) 仍能定位回显列', async () => {
  const httpClient = makeCaseScrambledUnionMock();
  const ctx = buildCtx(httpClient);
  const hits = await discoverEchoColumns(httpClient, ctx, 3);
  assert.deepEqual(hits, [0, 1, 2]);
});

// ===== 反例说明：若匹配是大小写敏感的，上面用例会失败（非空转保障）=====
// 说明：scrambleMarkerCase 把 'SQLISCANNER0' 变为 'sQlIsCaNnEr0'，
// 旧代码 body.includes('SQLISCANNER0') 在回显体里找不到 → 漏报；
// 新代码 body.toLowerCase().includes('sqliscanner0') 命中 → 通过。

// D6 标记免疫回归：验证 lowercase/uppercase/mixedcase 等 tamper 把 '__S__/__E__/__S__INL__E__'
// 标记整体改成小/大写后，提取层（extractScalar/extractInline）与检测层（InlineQueryDetector）
// 仍能正确匹配标记并返回数据，不再静默失效。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InlineQueryDetector } from '../src/engine/detectors/InlineQueryDetector.js';
import { INLINE_MARKER } from '../src/engine/detectors/InlineQueryDetector.js';

// 取出请求中的注入值（url query q）
function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 模拟"应用把参数值求值后以小写回显"（lowercase tamper 把 '__S__INL__E__' 变成 '__s__inl__e__'）
function lowercaseEchoClient() {
  return {
    async request(opts) {
      const v = extractQuery(opts);
      // 目标执行了子查询，结果被全量转小写后回显
      if (v.includes(`SELECT '${INLINE_MARKER}'`) || v.toLowerCase().includes(`select '${INLINE_MARKER.toLowerCase()}'`)) {
        return { status: 200, headers: {}, data: `result __s__inl__e__ end` };
      }
      return { status: 200, headers: {}, data: 'normal-page-no-marker' };
    },
  };
}

function makeCtx(httpClient, dbms = 'MySQL') {
  return {
    httpClient,
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url', dbms },
    config: {},
    dbms,
  };
}

test('D6: InlineQueryDetector 标记被 lowercase tamper 改小写后仍命中', async () => {
  const d = new InlineQueryDetector();
  const r = await d.detect(makeCtx(lowercaseEchoClient()));
  assert.equal(r.vulnerable, true, '小写标记 __s__inl__e__ 应被大小写不敏感匹配命中');
  assert.equal(r.technique, 'inline');
});

test('D6: InlineQueryDetector 标记被 uppercase tamper 改大写后仍命中', async () => {
  const d = new InlineQueryDetector();
  const upperClient = {
    async request(opts) {
      const v = extractQuery(opts);
      if (v.includes(`SELECT '${INLINE_MARKER}'`) || v.toUpperCase().includes(`SELECT '${INLINE_MARKER.toUpperCase()}'`)) {
        return { status: 200, headers: {}, data: `RESULT __S__INL__E__ END` };
      }
      return { status: 200, headers: {}, data: 'NORMAL-PAGE' };
    },
  };
  const r = await d.detect(makeCtx(upperClient));
  assert.equal(r.vulnerable, true, '大写标记 __S__INL__E__ 应被大小写不敏感匹配命中');
});

test('D6: 基线已含小写标记不应误报（大小写一致性）', async () => {
  const d = new InlineQueryDetector();
  const client = {
    async request() {
      // 基线和测试响应都含小写标记 → 排除误报
      return { status: 200, headers: {}, data: 'page always shows __s__inl__e__ tag' };
    },
  };
  const r = await d.detect(makeCtx(client));
  assert.equal(r.vulnerable, false, '基线与测试均含标记（小写）不应误报');
});

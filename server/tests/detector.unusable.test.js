// ============================================================================
// tests/detector.unusable.test.js —— 「没测成」不得被写成「没洞」
// [P0-FIX 2026-09-09]
//
// 判定层最坏的一类假安心：请求根本没发出去 / 被掐断 / 响应被截断，却被读成
// 「真页与假页无差异 → 该点不可注入」。布尔与时间两条通路都靠差异比对，
// 而差异比对的前提是「两侧都拿到了完整响应」——这个前提必须显式检查。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { netFailureResponse } from '../src/engine/egressOpts.js';

function truncatedRes(body) {
  const res = { status: 200, statusText: 'OK', headers: {}, data: body };
  Object.defineProperty(res, '__meta', {
    value: { truncated: true, bodyBytes: body.length },
    enumerable: false,
    configurable: true,
  });
  return res;
}

const ok = (body, status = 200) => ({ status, statusText: 'OK', headers: {}, data: body });

test('matchMetrics：不可用响应返回 null（未定），不是 false（无差异）', () => {
  const d = new Detector();
  const cfg = { matchCode: true };
  // 两侧都可用且确有差异 → 仍按原语义 true / false
  assert.equal(d.matchMetrics(ok('a', 200), ok('b', 500), cfg), true);
  assert.equal(d.matchMetrics(ok('a', 200), ok('b', 200), cfg), false);
  // 一侧网络失败 → 未定
  assert.equal(d.matchMetrics(netFailureResponse(new Error('ECONNREFUSED')), ok('b', 500), cfg), null);
  // 一侧被截断 → 未定（半张页面不能当证据）
  assert.equal(d.matchMetrics(truncatedRes('x'.repeat(10)), ok('yyy', 200), cfg), null);
  // 响应缺失（历史契约里的 null）→ 未定
  assert.equal(d.matchMetrics(null, ok('b', 500), cfg), null);
});

test('unusableOf 给出可读原因（供报告说明「该去查什么」）', () => {
  const d = new Detector();
  assert.equal(d.unusableOf(ok('x')), '');
  const why = d.unusableOf(
    netFailureResponse(Object.assign(new Error('connect ECONNREFUSED 1.2.3.4:80'), { code: 'ECONNREFUSED' }))
  );
  assert.match(why, /网络层失败/);
  assert.match(d.unusableOf(truncatedRes('abc')), /截断/);
});

// —— 检测器级：全部对照不可用 → 点标未决；有一对可用 → 正常下结论 ——
function ctxWith(responder, extra = {}) {
  const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1', boundary: "'" };
  const target = {
    mode: 'http',
    baseUrl: 'http://t.test/?id=1',
    method: 'GET',
    bodyParams: {},
    cookieParams: {},
    headerParams: {},
  };
  const httpClient = { async request(opts) { return responder(opts); } };
  return {
    point,
    target,
    dbms: 'MySQL',
    // boundary="'" 会产出一组显式真假对照（ti=-1），因此不依赖 templates 数组内容
    config: { matchCode: true, timeoutMs: 100, retry: 0, ...extra },
    httpClient,
  };
}

const freshResult = (pointId) => ({
  pointId,
  technique: 'boolean',
  vulnerable: false,
  payloads: [],
  evidence: '',
});

test('布尔多指标：所有对照都因网络失败不可用 → inconclusive，且不判 vulnerable', async () => {
  const det = new BooleanBlindDetector();
  let n = 0;
  const ctx = ctxWith(() => {
    n++;
    return netFailureResponse(new Error('socket hang up'));
  });
  const out = await det._matchMetricsDetect(ctx, freshResult(ctx.point.id), []);
  assert.ok(n >= 2, `应真的发出请求（实际 ${n} 次）`);
  assert.equal(out.vulnerable, false, '不可用响应绝不能被判成命中');
  assert.equal(out.inconclusive, true, '必须显式记为「未得出有效结论」');
  assert.match(String(out.inconclusiveReason), /网络层失败|响应不可用/);
});

test('布尔多指标：响应可用时结论照常（本次改动零回归）', async () => {
  const det = new BooleanBlindDetector();
  let n = 0;
  const ctx = ctxWith(() => {
    n++;
    // 奇数次=true 页（200），偶数次=false 页（500）→ 有差异 → 应命中
    return n % 2 === 1 ? ok('true page', 200) : ok('false page', 500);
  });
  const out = await det._matchMetricsDetect(ctx, freshResult(ctx.point.id), []);
  assert.ok(n >= 2, `应真的发出对照请求（实际 ${n} 次）`);
  assert.equal(out.vulnerable, true, `可用响应下的差异应照常命中（请求数=${n}）`);
  assert.equal(out.inconclusive, undefined);
  assert.equal(ctx.point.confirmed, true);
});

test('部分对照可用时不因个别失败误标未决（零星抖动不该废掉整点）', async () => {
  const det = new BooleanBlindDetector();
  let n = 0;
  const ctx = ctxWith(
    () => {
      n++;
      if (n <= 2) return netFailureResponse(new Error('timeout'));
      return n % 2 === 1 ? ok('true page', 200) : ok('false page', 500);
    },
    { useRegistry: true, level: 5, risk: 2 }
  );
  const out = await det._matchMetricsDetect(ctx, freshResult(ctx.point.id), []);
  assert.ok(n >= 4, `应至少跑到第二组对照（实际请求数=${n}）`);
  assert.equal(out.inconclusive, undefined, '只要有一对得出有效结论，就不该把整点标成未决');
  assert.equal(out.vulnerable, true);
});

// [P1-PERF 2026-11-02] 大响应热路径有界匹配集成回归：
//   每个用例都构造 **2MB 正文**，把签名放在**末尾**（旧窗口之外）——
//   证明窗口轮转没有把「全正文扫描」改成「只看前 512KB」，且不误报。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { hasBoundedMatch } from '../src/core/boundedMatch.js';
import { isBlockedResponse } from '../src/core/scanValidityGuard.js';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { looksBlocked } from '../src/core/waf/blockProfile.js';
import { NoSqlInjectionDetector } from '../src/engine/detectors/NoSqlInjectionDetector.js';
import { ERROR_SIG } from '../src/engine/payloads.js';

/** 2MB 前缀 + 末尾签名（确保不在第一个 512KB 窗口内） */
function bigBody(tail = '') {
  return 'x'.repeat(2 * 1024 * 1024) + tail;
}

/** 从检测器请求里取注入值（与 errorDetector.highfreq.test.js 同口径） */
function extractInjected(opts) {
  const url = String(opts?.url || '');
  const m = url.match(/[?&]q=([^&]*)/);
  if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  if (opts?.data && Object.keys(opts.data).length) return String(Object.values(opts.data)[0]);
  return '';
}

const MYSQL_ERR = "You have an error in your SQL syntax; near 'sqli' at line 1";

test('ErrorDetector：2MB 响应末尾的报错仍能命中（窗口轮转不截断）', async () => {
  const d = new ErrorDetector();
  const ctx = {
    httpClient: {
      async request(opts) {
        const v = extractInjected(opts);
        return { status: 200, headers: {}, data: v.includes('extractvalue') ? bigBody(MYSQL_ERR) : bigBody() };
      },
    },
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: { level: 1 },
    dbms: null,
  };
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, true, '末尾报错签名应被有界匹配命中');
  assert.equal(r.dbms, 'MySQL');
});

test('ErrorDetector：基线也在 2MB 末尾报同样的错 → 视为页面固有，不误报', async () => {
  const d = new ErrorDetector();
  const ctx = {
    httpClient: {
      async request() {
        return { status: 200, headers: {}, data: bigBody(MYSQL_ERR) };
      },
    },
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: { level: 1 },
    dbms: null,
  };
  const r = await d.detect(ctx);
  assert.equal(r.vulnerable, false, '基线末尾命中必须能与探针同签名抵消');
});

test('有界匹配本身：2MB 末尾命中 / 干净大正文不误报', () => {
  assert.ok(hasBoundedMatch(bigBody(MYSQL_ERR), ERROR_SIG), 'ERROR_SIG 末尾命中');
  assert.equal(hasBoundedMatch(bigBody(), ERROR_SIG), false, '2MB 健康页不应命中');
});

test('scanValidityGuard：4xx 大响应末尾的拦截文案仍判 blocked', () => {
  // 400 不在 BLOCK_STATUSES，走文案通道；旧实现全文 test，新实现窗口 test，两者语义应一致
  assert.equal(isBlockedResponse({ status: 400, data: bigBody('access denied') }), true);
  assert.equal(isBlockedResponse({ status: 400, data: bigBody() }), false);
  // 200 页面即使末尾有拦截字样也不得判 blocked（状态码门槛仍在，未被有界化改掉）
  assert.equal(isBlockedResponse({ status: 200, data: bigBody('access denied') }), false);
});

test('WafIdentifier：2MB 拦截页末尾的厂商特征仍能识别', () => {
  const id = new WafIdentifier();
  const r = id.identify({ status: 200, headers: { server: 'nginx' }, body: bigBody('<html>ModSecurity</html>') });
  assert.ok(
    r.some((c) => /body~\/modsecurity/i.test(c.evidence)),
    `应命中 ModSecurity 的 body matcher，实得 ${JSON.stringify(r)}`
  );
});

test('blockProfile.looksBlocked(strict)：2MB 末尾拦截文案仍判被拦', () => {
  assert.equal(looksBlocked({ status: 200, data: bigBody('access denied') }, 0, { strict: true }), true);
  assert.equal(looksBlocked({ status: 200, data: bigBody() }, 0, { strict: true }), false);
});

test('NoSqlInjectionDetector SSTI：2MB 响应末尾的求值回显仍命中', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const v = extractInjected(req);
      return { status: 200, headers: {}, data: v.includes('{{7*7}}') ? bigBody(' result: 49 ') : bigBody() };
    },
  };
  const r = await d.detect({
    httpClient: client,
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: {},
    noSqlKind: 'ssti',
  });
  assert.equal(r.vulnerable, true, 'SSTI 末尾回显应被有界匹配命中');
  assert.equal(r.noSqlKind, 'ssti');
});

test('NoSqlInjectionDetector GraphQL：2MB 响应末尾的回显仍命中；基线同回显则不误报', async () => {
  const ctxFor = (baselineTail) => ({
    httpClient: {
      async request(req) {
        const v = extractInjected(req);
        return { status: 200, headers: {}, data: v.includes('__schema') ? bigBody('{"data":{"__schema":{}}}') : bigBody(baselineTail) };
      },
    },
    target: { baseUrl: 'http://x/' },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    config: {},
    noSqlKind: 'graphql',
  });
  const hit = await new NoSqlInjectionDetector().detect(ctxFor(''));
  assert.equal(hit.vulnerable, true, '末尾 __schema 回显应命中');
  const noise = await new NoSqlInjectionDetector().detect(ctxFor('{"data":{"__schema":{}}}'));
  assert.equal(noise.vulnerable, false, '基线末尾已含同一回显 → 不误报');
});

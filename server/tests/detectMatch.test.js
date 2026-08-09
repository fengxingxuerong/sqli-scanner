// 自定义检测判定锚点（对标 sqlmap --string/--not-string/--regexp/--code）纯函数单测
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDetectMatch,
  evaluateDetectMatch,
  validateDetectMatch,
} from '../src/engine/detectionMatch.js';
import { ErrorCode } from '../src/core/errors.js';

test('normalizeDetectMatch：全空 → null（不激活）', () => {
  assert.equal(normalizeDetectMatch({}), null);
  assert.equal(normalizeDetectMatch({ detectMatch: { string: null, notString: '', regexp: '', code: null } }), null);
  assert.equal(normalizeDetectMatch(undefined), null);
});

test('normalizeDetectMatch：解析 string/notString/code，忽略非法正则', () => {
  const m = normalizeDetectMatch({ detectMatch: { string: 'abc', notString: 'xyz', regexp: '[(', code: 200 } });
  assert.equal(m.string, 'abc');
  assert.equal(m.notString, 'xyz');
  assert.equal(m.code, 200);
  assert.equal(m.regexp, undefined, '非法正则被忽略');
});

test('normalizeDetectMatch：合法正则编译为 RegExp', () => {
  const m = normalizeDetectMatch({ detectMatch: { regexp: 'err_[0-9]+' } });
  assert.ok(m.regexp instanceof RegExp);
  assert.equal(m.regexp.test('err_42'), true);
});

test('evaluateDetectMatch：string 锚点 TRUE含/FALSE不含 → 通过', () => {
  const r = evaluateDetectMatch(
    { string: 'ADMIN' },
    { trueBody: 'welcome ADMIN panel', falseBody: 'access denied', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r.vulnerable, true);
});

test('evaluateDetectMatch：string 锚点 FALSE也含 → 不通过', () => {
  const r = evaluateDetectMatch(
    { string: 'ADMIN' },
    { trueBody: 'welcome ADMIN', falseBody: 'denied ADMIN', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r.vulnerable, false);
  assert.ok(r.evidence.includes('FAIL'));
});

test('evaluateDetectMatch：notString 锚点 TRUE不含/FALSE含 → 通过', () => {
  const r = evaluateDetectMatch(
    { notString: 'ERROR' },
    { trueBody: 'ok', falseBody: 'query ERROR occurred', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r.vulnerable, true);
});

test('evaluateDetectMatch：regexp 锚点 TRUE匹配/FALSE不匹配 → 通过', () => {
  const r = evaluateDetectMatch(
    { regexp: /user_\d+/ },
    { trueBody: 'found user_77', falseBody: 'nothing', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r.vulnerable, true);
  const r2 = evaluateDetectMatch(
    { regexp: /user_\d+/ },
    { trueBody: 'found user_77', falseBody: 'found user_88', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r2.vulnerable, false, 'FALSE 也匹配正则 → 不通过');
});

test('evaluateDetectMatch：code 锚点 TRUE状态码匹配/FALSE不匹配 → 通过', () => {
  const r = evaluateDetectMatch(
    { code: 500 },
    { trueBody: 'x', falseBody: 'y', trueStatus: 500, falseStatus: 200 }
  );
  assert.equal(r.vulnerable, true);
  const r2 = evaluateDetectMatch(
    { code: 500 },
    { trueBody: 'x', falseBody: 'y', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(r2.vulnerable, false, 'FALSE 也等于 code → 不通过');
});

test('evaluateDetectMatch：多锚点 AND 语义（全部通过才 vulnerable）', () => {
  const good = evaluateDetectMatch(
    { string: 'OK', code: 200 },
    { trueBody: 'OK page', falseBody: 'nope', trueStatus: 200, falseStatus: 403 }
  );
  assert.equal(good.vulnerable, true);
  const bad = evaluateDetectMatch(
    { string: 'OK', code: 200 },
    { trueBody: 'OK page', falseBody: 'nope', trueStatus: 200, falseStatus: 200 }
  );
  assert.equal(bad.vulnerable, false, 'code 锚点失败 → 整体不通过');
});

test('validateDetectMatch：非法正则抛 INVALID_PARAM', () => {
  assert.throws(
    () => validateDetectMatch({ detectMatch: { regexp: '[' } }),
    (e) => e instanceof Error && e.code === ErrorCode.INVALID_PARAM
  );
});

test('validateDetectMatch：非法 code 抛 INVALID_PARAM', () => {
  assert.throws(
    () => validateDetectMatch({ detectMatch: { code: 'abc' } }),
    (e) => e instanceof Error && e.code === ErrorCode.INVALID_PARAM
  );
});

test('validateDetectMatch：合法配置放行', () => {
  assert.equal(validateDetectMatch({ detectMatch: { string: 'x', code: 200 } }), true);
  assert.equal(validateDetectMatch({}), true);
});

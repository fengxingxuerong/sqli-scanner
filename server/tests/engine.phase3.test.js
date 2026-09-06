// Phase 3 引擎能力补齐回归：
//   T1 — payload 前缀/后缀（对标 sqlmap --prefix / --suffix）
//   T2 — HTTP 方法 PUT/PATCH/DELETE（对标 sqlmap --data 多方法）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest, applyPrefixSuffix } from '../src/engine/injection.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';
import { ErrorCode, AppError } from '../src/core/errors.js';

// ── T1：prefix/suffix 拼接 ───────────────────────────────────────

test('applyPrefixSuffix：注入值包裹 prefix+suffix（= prefix + 原值 + payload + suffix）', () => {
  const target = { mode: 'http', config: { prefix: "'", suffix: '-- -' } };
  const point = { originalValue: '1' };
  // value 由调用方拼成「原值 + payload」，此处模拟 "1' AND 1=1"
  assert.equal(applyPrefixSuffix(target, point, "1' AND 1=1"), "'1' AND 1=1-- -");
});

test('applyPrefixSuffix：默认空 prefix/suffix 不改变注入值（向后兼容）', () => {
  const target = { mode: 'http', config: {} };
  const point = { originalValue: '1' };
  assert.equal(applyPrefixSuffix(target, point, '1 AND 1=1'), '1 AND 1=1');
});

test('applyPrefixSuffix：基线请求（value 恰为原始值）不包裹', () => {
  const target = { mode: 'http', config: { prefix: "'", suffix: '-- -' } };
  const point = { originalValue: '1' };
  assert.equal(applyPrefixSuffix(target, point, '1'), '1');
});

test('applyPrefixSuffix：原始值为空时基线 "1" 不包裹', () => {
  const target = { mode: 'http', config: { prefix: "'", suffix: '-- -' } };
  const point = { originalValue: '' };
  assert.equal(applyPrefixSuffix(target, point, '1'), '1');
});

test('applyPrefixSuffix：直连模式不包裹', () => {
  const target = { mode: 'direct', sqlTemplate: 'SELECT {INJECT}', config: { prefix: "'", suffix: '-- -' } };
  const point = { originalValue: '1' };
  assert.equal(applyPrefixSuffix(target, point, '1 AND 1=1'), '1 AND 1=1');
});

test('buildInjectionRequest：URL 注入点最终值为 prefix + 原值 + payload + suffix', () => {
  const target = {
    method: 'GET',
    baseUrl: 'http://example.com/page?id=1',
    headerParams: {},
    cookieParams: {},
    config: { prefix: "'", suffix: '-- -' },
  };
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1' AND 1=1");
  assert.equal(req.method, 'GET');
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), "'1' AND 1=1-- -");
});

test('buildInjectionRequest：body 注入点包裹 prefix/suffix', () => {
  const target = {
    method: 'POST',
    baseUrl: 'http://example.com/api',
    headerParams: {},
    cookieParams: {},
    config: { prefix: "')", suffix: '-- -' },
  };
  const point = { location: 'body', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1') AND 1=1");
  assert.equal(req.method, 'POST');
  assert.equal(req.data.id, "')1') AND 1=1-- -");
});

test('buildInjectionRequest：基线请求不被 prefix/suffix 污染', () => {
  const target = {
    method: 'GET',
    baseUrl: 'http://example.com/page?id=1',
    headerParams: {},
    cookieParams: {},
    config: { prefix: "'", suffix: '-- -' },
  };
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, '1'); // 基线
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1');
});

// ── T2：HTTP 方法 PUT/PATCH/DELETE ───────────────────────────────

test('sanitizeStart：非法 method 抛 INVALID_PARAM', () => {
  assert.throws(
    () => sanitizeStart({ url: 'http://x/?id=1', method: 'TRACE' }),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM
  );
  assert.throws(
    () => sanitizeStart({ url: 'http://x/?id=1', method: 'HEAD' }),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM
  );
});

test('sanitizeStart：PUT/PATCH/DELETE 方法通过并归一化为大写', () => {
  for (const m of ['put', 'PATCH', 'delete', 'POST', 'GET']) {
    const out = sanitizeStart({ url: 'http://x/?id=1', method: m });
    assert.equal(out.method, m.toUpperCase());
  }
});

test('sanitizeStart：prefix/suffix 收编进 config，超长截断到 200', () => {
  const out = sanitizeStart({
    url: 'http://x/?id=1',
    method: 'GET',
    config: { prefix: "'", suffix: 'a'.repeat(300) },
  });
  assert.equal(out.config.prefix, "'");
  assert.equal(out.config.suffix, 'a'.repeat(200));
});

test('sanitizeStart：未提供 prefix/suffix 时不写入 config（引擎沿用 defaults 空串）', () => {
  const out = sanitizeStart({ url: 'http://x/?id=1', method: 'GET', config: {} });
  assert.equal(out.config.prefix, undefined);
  assert.equal(out.config.suffix, undefined);
});

test('TargetParser：PUT/PATCH/DELETE 解析 bodyParams 为 body 注入点', async () => {
  const parser = new TargetParser();
  for (const m of ['PUT', 'PATCH', 'DELETE']) {
    const target = createTarget({
      url: 'http://example.com/api',
      method: m,
      bodyParams: { id: '1', name: 'x' },
    });
    const points = await parser.discover(target);
    const bodyPoints = points.filter((p) => p.location === 'body');
    assert.deepEqual(
      bodyPoints.map((p) => p.param).sort(),
      ['id', 'name'],
      `${m} 应解析 body 参数`
    );
  }
});

test('TargetParser：GET 同样解析 bodyParams（向后兼容既有行为）', async () => {
  const parser = new TargetParser();
  const target = createTarget({
    url: 'http://example.com/page',
    method: 'GET',
    bodyParams: { a: '1' },
  });
  const points = await parser.discover(target);
  assert.ok(points.some((p) => p.location === 'body' && p.param === 'a'));
});

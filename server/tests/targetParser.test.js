// TargetParser + models.js 单元测试
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import {
  createTarget,
  createInjectionPoint,
  createDetectionResult,
  createVulnerability,
  createReport,
  emptyExtractedData,
} from '../src/engine/models.js';
import { ErrorCode, AppError } from '../src/core/errors.js';

const parser = new TargetParser();

// ===== TargetParser =====
test('发现 GET URL 查询参数注入点', async () => {
  const target = createTarget({ url: 'http://example.com/page?id=1&name=foo' });
  const points = await parser.discover(target);
  const ids = points.map((p) => p.param);
  assert.ok(ids.includes('id'));
  assert.ok(ids.includes('name'));
  const idPoint = points.find((p) => p.param === 'id');
  assert.equal(idPoint.location, 'url');
  assert.equal(idPoint.originalValue, '1');
});

test('发现 POST body 注入点', async () => {
  const target = createTarget({
    url: 'http://example.com/login',
    method: 'POST',
    bodyParams: { user: 'admin', pass: 'x' },
  });
  const points = await parser.discover(target);
  const params = points.map((p) => p.param);
  assert.deepEqual(params, ['user', 'pass']);
  assert.ok(points.every((p) => p.location === 'body'));
});

test('发现 Cookie 注入点（level>=2）', async () => {
  // 默认 level=1 不测 Cookie；需显式 level>=2 才扩展 Cookie 注入点
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 2 },
    cookieParams: { session: 'abc', track: '1' },
  });
  const points = await parser.discover(target);
  const params = points.map((p) => p.param).sort();
  assert.deepEqual(params, ['session', 'track']);
  assert.ok(points.every((p) => p.location === 'cookie'));
  // level=2 不应自动注入 UA/Referer 头
  assert.ok(!points.some((p) => /^user-agent$/i.test(p.param)));
});

test('发现 Header 注入点（level>=3）', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 3 },
    headerParams: { 'X-Forwarded-For': '1.2.3.4' },
  });
  const points = await parser.discover(target);
  const xff = points.find((p) => p.param === 'X-Forwarded-For');
  assert.ok(xff, '显式 Header 注入点被发现');
  assert.equal(xff.location, 'header');
  // level>=3 自动注入常见请求头 User-Agent / Referer（未被显式列举时）
  const params = points.map((p) => p.param.toLowerCase());
  assert.ok(params.includes('user-agent'), '自动注入 User-Agent 头');
  assert.ok(params.includes('referer'), '自动注入 Referer 头');
});

test('多位置注入点可同时发现（level>=3）', async () => {
  const target = createTarget({
    url: 'http://example.com/search?q=hi',
    method: 'POST',
    config: { level: 3 },
    bodyParams: { category: 'book' },
    cookieParams: { cid: '9' },
    headerParams: { Referer: 'x' },
  });
  const points = await parser.discover(target);
  const byLoc = {};
  for (const p of points) byLoc[p.location] = (byLoc[p.location] || 0) + 1;
  assert.equal(byLoc.url, 1);
  assert.equal(byLoc.body, 1);
  assert.equal(byLoc.cookie, 1);
  // header：显式 Referer + 自动 User-Agent（Referer 已显式提供不再叠加）
  assert.ok(byLoc.header >= 1, 'header 注入点至少 1 个（显式 Referer + 自动 User-Agent）');
  assert.ok(points.some((p) => p.param === 'Referer'), '显式 Referer 命中');
  assert.ok(points.some((p) => p.param === 'User-Agent'), '自动 User-Agent 命中');
});

test('非法 URL 不抛出，仅跳过 URL 参数', async () => {
  const target = { baseUrl: 'not a url ::', bodyParams: { a: '1' }, cookieParams: {}, headerParams: {} };
  const points = await parser.discover(target);
  assert.equal(points.length, 1);
  assert.equal(points[0].param, 'a');
  assert.equal(points[0].location, 'body');
});

// ===== models 工厂 =====
test('createTarget 校验：缺少 url 抛 INVALID_TARGET', () => {
  assert.throws(
    () => createTarget({}),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_TARGET
  );
});

test('createTarget 校验：非法 method 抛 UNSUPPORTED_METHOD', () => {
  assert.throws(
    () => createTarget({ url: 'http://x', method: 'DELETE' }),
    (e) => e.code === ErrorCode.UNSUPPORTED_METHOD
  );
});

test('createTarget 默认 method 为 GET 且合并 config', () => {
  const t = createTarget({ url: 'http://x' });
  assert.equal(t.method, 'GET');
  assert.ok(t.config && typeof t.config.timeoutMs === 'number');
  assert.ok(typeof t.id === 'string' && t.id.length > 0);
});

test('createInjectionPoint 字段完整（含表单扩展默认 null）', () => {
  const p = createInjectionPoint('url', 'id', '5');
  assert.equal(p.location, 'url');
  assert.equal(p.param, 'id');
  assert.equal(p.originalValue, '5');
  assert.equal(p.confirmed, false);
  assert.equal(p.technique, null);
  assert.ok(p.id);
  // 新增表单字段默认 null/{}（向后兼容）
  assert.equal(p.formMethod, null);
  assert.equal(p.actionUrl, null);
  assert.equal(p.formValues, null);
  assert.equal(p.csrfTokenName, null);
});

test('createInjectionPoint 表单点携带扩展字段', () => {
  const p = createInjectionPoint('body', 'username', 'admin', {
    formMethod: 'POST',
    actionUrl: 'http://x.com/login',
    formValues: { username: 'admin', _token: 't' },
    csrfTokenName: '_token',
  });
  assert.equal(p.formMethod, 'POST');
  assert.equal(p.actionUrl, 'http://x.com/login');
  assert.deepEqual(p.formValues, { username: 'admin', _token: 't' });
  assert.equal(p.csrfTokenName, '_token');
});

test('createDetectionResult 默认未命中', () => {
  const r = createDetectionResult('pid', 'union');
  assert.equal(r.vulnerable, false);
  assert.equal(r.technique, 'union');
  assert.equal(r.dbms, null);
});

test('createVulnerability 字段完整', () => {
  const v = createVulnerability('pid', 'error', 'High', ['p1'], 'ev');
  assert.equal(v.technique, 'error');
  assert.equal(v.riskLevel, 'High');
  assert.deepEqual(v.payloads, ['p1']);
  assert.equal(v.dbms, null);
});

test('emptyExtractedData 结构', () => {
  assert.deepEqual(emptyExtractedData(), {
    databases: [],
    tables: {},
    columns: {},
    rows: {},
  });
});

test('createReport 初始风险为 Low 且含 scanId', () => {
  const t = createTarget({ url: 'http://x' });
  const r = createReport('scan-1', t);
  assert.equal(r.scanId, 'scan-1');
  assert.equal(r.riskLevel, 'Low');
  assert.equal(r.finishedAt, null);
  assert.deepEqual(r.points, []);
  assert.deepEqual(r.vulns, []);
});

// ===== 表单扩展字段默认（非表单点）=====
test('非表单注入点新字段默认为 null/{}（向后兼容）', async () => {
  const target = createTarget({ url: 'http://example.com/page?id=1&name=foo' });
  const points = await parser.discover(target);
  assert.ok(points.length > 0);
  for (const p of points) {
    assert.equal(p.formMethod, null);
    assert.equal(p.actionUrl, null);
    assert.equal(p.formValues, null);
    assert.equal(p.csrfTokenName, null);
  }
});

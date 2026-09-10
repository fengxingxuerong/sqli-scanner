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

test('发现 Cookie 注入点', async () => {
  const target = createTarget({
    url: 'http://example.com',
    cookieParams: { session: 'abc', track: '1' },
    config: { level: 2 },
  });
  const points = await parser.discover(target);
  const params = points.map((p) => p.param).sort();
  assert.deepEqual(params, ['session', 'track']);
  assert.ok(points.every((p) => p.location === 'cookie'));
});

test('发现 Header 注入点', async () => {
  const target = createTarget({
    url: 'http://example.com',
    headerParams: { 'X-Forwarded-For': '1.2.3.4' },
    config: { level: 4 },
  });
  const points = await parser.discover(target);
  assert.equal(points.length, 1);
  assert.equal(points[0].location, 'header');
  assert.equal(points[0].param, 'X-Forwarded-For');
});

// [2026-09-10] 默认 level=1 不发现 header 注入点 —— 这是有意的（header 探测会显著增加
// 请求数），但它同时意味着「请求头通道」在默认配置下是**盲区**。
// 请求头通道的价值（e2e/waf-real/header-channel.mjs 实测，真实 MySQL + CRS v4.1.0）：
//   同一个 SQL 注入点，走 URL 参数被 CRS 拦 73 次、只检出 boolean；
//   走自定义请求头被拦 **0 次**、level>=3 时 union/error/boolean 三技术位全检出。
// 即：WAF 面前，请求头是「通道绕过」面。锁住 level 分级语义，避免有人随手改默认值。
test('默认 level=1：不发现 header 注入点（请求头通道需显式 level>=3）', async () => {
  const target = createTarget({
    url: 'http://example.com',
    headerParams: { 'X-User-Id': '1' },
    config: { level: 1 },
  });
  const points = await parser.discover(target);
  assert.equal(points.filter((p) => p.location === 'header').length, 0);
});

test('level=3 发现非敏感 header 注入点，但仍排除敏感头（authorization/cookie/host/xff）', async () => {
  const target = createTarget({
    url: 'http://example.com',
    headerParams: {
      'X-User-Id': '1',
      Referer: 'http://r',
      Authorization: 'Bearer t',
      Cookie: 'c=1',
      'X-Forwarded-For': '1.2.3.4',
    },
    config: { level: 3 },
  });
  const points = await parser.discover(target);
  const names = points.filter((p) => p.location === 'header').map((p) => p.param).sort();
  assert.deepEqual(names, ['Referer', 'X-User-Id']);
});

test('多位置注入点可同时发现', async () => {
  const target = createTarget({
    url: 'http://example.com/search?q=hi',
    method: 'POST',
    bodyParams: { category: 'book' },
    cookieParams: { cid: '9' },
    headerParams: { Referer: 'x' },
    config: { level: 3 },
  });
  const points = await parser.discover(target);
  const byLoc = {};
  for (const p of points) byLoc[p.location] = (byLoc[p.location] || 0) + 1;
  assert.equal(byLoc.url, 1);
  assert.equal(byLoc.body, 1);
  assert.equal(byLoc.cookie, 1);
  assert.equal(byLoc.header, 1);
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
    () => createTarget({ url: 'http://x', method: 'TRACE' }),
    (e) => e.code === ErrorCode.UNSUPPORTED_METHOD
  );
});

test('createTarget 支持 PUT/PATCH/DELETE 方法（P2-A5）', () => {
  for (const m of ['PUT', 'PATCH', 'DELETE']) {
    const t = createTarget({ url: 'http://x', method: m });
    assert.equal(t.method, m);
  }
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
    hostname: undefined,
    isDba: undefined,
    schemas: {},
    userPrivs: undefined,
    roles: undefined,
    currentDb: undefined,
    currentUser: undefined,
    users: undefined,
    passwords: undefined,
    counts: {},
    search: undefined,
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

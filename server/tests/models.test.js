import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTarget, createInjectionPoint, createVulnerability, emptyExtractedData, createReport } from '../src/engine/models.js';
import { ErrorCode } from '../src/core/errors.js';

test('createTarget HTTP 模式：返回完整目标结构', () => {
  const t = createTarget({ url: 'http://test.local/api', method: 'POST' });
  assert.equal(t.mode, 'http');
  assert.equal(t.baseUrl, 'http://test.local/api');
  assert.equal(t.method, 'POST');
  assert.ok(t.id);
});

test('createTarget HTTP 模式：method 白名单 GET/POST/PUT/PATCH/DELETE', () => {
  const t = createTarget({ url: 'http://test.local', method: 'delete' });
  assert.equal(t.method, 'DELETE');
  assert.throws(() => createTarget({ url: 'http://test.local', method: 'OPTIONS' }), { code: ErrorCode.UNSUPPORTED_METHOD });
  assert.throws(() => createTarget({ url: 'http://test.local', method: 'HEAD' }), { code: ErrorCode.UNSUPPORTED_METHOD });
});

test('createTarget direct 模式：校验 db/connectionString 和 sqlTemplate 含 {INJECT}', () => {
  const t = createTarget({ mode: 'direct', db: { driverType: 'memory' }, sqlTemplate: 'SELECT * FROM t WHERE id = {INJECT}' });
  assert.equal(t.mode, 'direct');
  assert.equal(t.sqlTemplate, 'SELECT * FROM t WHERE id = {INJECT}');
  assert.ok(t.id);
  assert.throws(() => createTarget({ mode: 'direct', sqlTemplate: 'SELECT 1' }), { code: ErrorCode.INVALID_TARGET });
  assert.throws(() => createTarget({ mode: 'direct', db: { driverType: 'memory' }, sqlTemplate: 'SELECT 1' }), { code: ErrorCode.INVALID_TARGET });
  assert.throws(() => createTarget({ mode: 'direct', sqlTemplate: 'SELECT * FROM t WHERE id = {INJECT}' }), { code: ErrorCode.INVALID_TARGET });
});

test('createTarget 非法 URL 抛 INVALID_TARGET', () => {
  assert.throws(() => createTarget({}), { code: ErrorCode.INVALID_TARGET });
  assert.throws(() => createTarget({ url: '' }), { code: ErrorCode.INVALID_TARGET });
  assert.throws(() => createTarget(null), { code: ErrorCode.INVALID_TARGET });
});

test('createInjectionPoint 字段完整', () => {
  const p = createInjectionPoint('url', 'id', '1');
  assert.equal(p.location, 'url');
  assert.equal(p.param, 'id');
  assert.equal(p.originalValue, '1');
  assert.equal(p.confirmed, false);
  assert.equal(p.technique, null);
  assert.equal(p.dbms, null);
  assert.ok(p.id);
  assert.equal(p.formMethod, null);
  assert.equal(p.actionUrl, null);
});

test('createInjectionPoint 表单额外字段', () => {
  const p = createInjectionPoint('body', 'user', 'admin', { formMethod: 'POST', actionUrl: 'http://t/login', formValues: { user: 'admin', pass: 'x' } });
  assert.equal(p.formMethod, 'POST');
  assert.equal(p.actionUrl, 'http://t/login');
  assert.equal(p.formValues.user, 'admin');
});

test('createVulnerability 风险定级', () => {
  const v = createVulnerability('p1', 'union', 'High', ["' UNION SELECT 1-- -"], 'Found UNION injection');
  assert.equal(v.riskLevel, 'High');
  assert.equal(v.technique, 'union');
  assert.equal(v.description, 'Found UNION injection');
  assert.equal(v.evidence, 'Found UNION injection');
  assert.ok(v.id);
  assert.equal(v.trace, null);
  assert.deepEqual(v.payloads, ["' UNION SELECT 1-- -"]);
});

test('createVulnerability 中等风险', () => {
  const v = createVulnerability('p2', 'boolean', 'Medium', [], 'Blind boolean');
  assert.equal(v.riskLevel, 'Medium');
});

test('emptyExtractedData 结构正确', () => {
  const d = emptyExtractedData();
  assert.deepEqual(d, {
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
  const t = createTarget({ url: 'http://test.local' });
  const r = createReport('scan-123', t);
  assert.equal(r.riskLevel, 'Low');
  assert.equal(r.scanId, 'scan-123');
  assert.equal(r.target.baseUrl, 'http://test.local');
  assert.equal(r.finishedAt, null);
  assert.deepEqual(r.points, []);
  assert.deepEqual(r.vulns, []);
  assert.equal(r.data, null);
});
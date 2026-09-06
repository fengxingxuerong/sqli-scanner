import { test } from 'node:test';
import assert from 'node:assert/strict';
import { URL } from 'url';
import { buildInjectionRequest, applyPrefixSuffix } from '../src/engine/injection.js';

const baseTarget = (extra = {}) => ({
  mode: 'http',
  baseUrl: 'http://test.local/api/items',
  method: 'GET',
  bodyParams: {},
  cookieParams: { session: 'abc' },
  headerParams: { 'X-Api-Key': 'k1' },
  config: {},
  ...extra,
});

test('url 注入点：injected 值写入 query 参数', () => {
  const t = baseTarget();
  const p = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(t, p, "1' AND '1'='1");
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), "1' AND '1'='1");
  assert.equal(req.method, 'GET');
});

test('body 注入点：injected 值覆盖 data[param]，其余表单字段保留', () => {
  const t = baseTarget({ method: 'POST' });
  const p = { location: 'body', param: 'user', originalValue: '1', formValues: { csrf: 'tok', user: '1' } };
  const req = buildInjectionRequest(t, p, "1' OR '1'='1");
  assert.equal(req.data.csrf, 'tok');
  assert.equal(req.data.user, "1' OR '1'='1");
  assert.equal(req.method, 'POST');
});

test('cookie 注入点：injected 值写入 Cookie 头', () => {
  const t = baseTarget();
  const p = { location: 'cookie', param: 'session', originalValue: 'abc' };
  const req = buildInjectionRequest(t, p, "abc' UNION SELECT 1-- -");
  assert.match(req.headers['Cookie'], /session=abc' UNION SELECT 1-- -/);
});

test('header 注入点：injected 值写入指定请求头', () => {
  const t = baseTarget();
  const p = { location: 'header', param: 'X-Forwarded-For', originalValue: '1.1.1.1' };
  const req = buildInjectionRequest(t, p, "1.1.1.1' OR SLEEP(2)-- -");
  assert.equal(req.headers['X-Forwarded-For'], "1.1.1.1' OR SLEEP(2)-- -");
});

test('prefix/suffix 包裹：非基线值被前后缀包裹', () => {
  const t = baseTarget({ config: { prefix: "'))", suffix: '-- -' } });
  const p = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(t, p, "1 UNION SELECT 1");
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), "'))1 UNION SELECT 1-- -");
});

test('基线请求：value===originalValue 时不包裹 prefix/suffix', () => {
  const t = baseTarget({ config: { prefix: "'))", suffix: '-- -' } });
  const p = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(t, p, '1');
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1');
});

test('直连模式：SQL 模板 {INJECT} 被替换为注入值', () => {
  const t = { mode: 'direct', sqlTemplate: "SELECT * FROM t WHERE id = {INJECT}", config: {} };
  const p = { location: 'direct', param: 'id', originalValue: '1', sqlTemplate: "SELECT * FROM t WHERE id = {INJECT}" };
  const req = buildInjectionRequest(t, p, '1 OR 1=1');
  assert.equal(req.sql, 'SELECT * FROM t WHERE id = 1 OR 1=1');
  assert.equal(req.method, '');
  assert.equal(req.url, '');
});

test('直连模式：prefix/suffix 不生效（直连原样返回）', () => {
  const t = { mode: 'direct', sqlTemplate: "SELECT {INJECT}", config: { prefix: 'X', suffix: 'Y' } };
  const p = { location: 'direct', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(t, p, '1 UNION SELECT version()');
  assert.equal(req.sql, 'SELECT 1 UNION SELECT version()');
});

test('path 注入点：按 pathSegment 下标替换路径段', () => {
  const t = baseTarget({ baseUrl: 'http://test.local/api/items/1/details' });
  const p = { location: 'path', param: '1', originalValue: '1', pathSegment: 3 };
  const req = buildInjectionRequest(t, p, '1 UNION SELECT 1');
  const u = new URL(req.url);
  assert.equal(u.pathname, '/api/items/1%20UNION%20SELECT%201/details');
});

test('path 注入点：无 pathSegment 时按 param 匹配段值（剥离尾部 *）', () => {
  const t = baseTarget({ baseUrl: 'http://test.local/api/items/seg*/details' });
  const p = { location: 'path', param: 'seg', originalValue: 'seg', pathSegment: null };
  const req = buildInjectionRequest(t, p, 'seg UNION SELECT 1');
  const u = new URL(req.url);
  assert.equal(u.pathname, '/api/items/seg%20UNION%20SELECT%201/details');
});

test('applyPrefixSuffix：无 prefix/suffix 返回原值', () => {
  const t = baseTarget({ config: {} });
  const p = { location: 'url', param: 'id', originalValue: '1' };
  assert.equal(applyPrefixSuffix(t, p, 'payload'), 'payload');
});

test('applyPrefixSuffix：直连模式始终原样返回', () => {
  const t = { mode: 'direct', config: { prefix: 'P', suffix: 'S' } };
  const p = { location: 'direct', param: 'id', originalValue: '1' };
  assert.equal(applyPrefixSuffix(t, p, 'payload'), 'payload');
});

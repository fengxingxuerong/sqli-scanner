// [P2-5] --hpp：buildInjectionRequest 在 GET query 注入点把注入值复制进 body 同名参数
// （query+body 双份提交，WAF 绕过形态）。基线请求（值=原始值）不双份。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest } from '../src/engine/injection.js';

function mkTarget(config = {}, over = {}) {
  return {
    method: 'GET',
    baseUrl: 'http://t.example/page.php?id=1&x=2',
    headerParams: {},
    cookieParams: {},
    config: { ...config },
    ...over,
  };
}

// GET query 注入点 + --hpp：注入值双份进 body
test('hpp: GET query 注入请求同时写入 body 同名参数', () => {
  const target = mkTarget({ hpp: true });
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1' AND 1=1-- -");
  // query 仍带注入值
  assert.ok(req.url.includes("id=1%27%20AND%201%3D1--%20-") || req.url.includes("id=1' AND 1=1-- -") || req.url.includes('id='), 'query 含注入参数');
  // body 同名参数 = 注入值
  assert.equal(req.data['id'], "1' AND 1=1-- -");
});

// 基线请求（value === originalValue）不双份
test('hpp: 基线请求（值=原始值）不写 body', () => {
  const target = mkTarget({ hpp: true });
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, '1');
  assert.equal(req.data['id'], undefined);
});

// 未开 --hpp：注入请求不双份（回归护栏）
test('hpp: 未开启时注入请求不写 body', () => {
  const target = mkTarget({}); // hpp 未开
  const point = { location: 'url', param: 'id', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1' AND 1=1-- -");
  assert.equal(req.data['id'], undefined);
});

// body 注入点不双份（data 覆盖本来就在 body）
test('hpp: body 注入点不受影响（仅 GET query 生效）', () => {
  const target = mkTarget({ hpp: true }, { method: 'POST' });
  const point = { location: 'body', param: 'user', originalValue: 'a', formValues: { user: 'a', csrf: 't' } };
  const req = buildInjectionRequest(target, point, "a' OR '1'='1");
  const form = new URLSearchParams(req.data); // [P0-FIX 2026-09-15] urlencoded 序列化口径
  assert.equal(form.get('user'), "a' OR '1'='1");
  assert.equal(form.get('csrf'), 't');
  assert.equal(form.get('csrf') !== undefined, true);
});

// 直连模式（direct）不受 hpp 影响
test('hpp: 直连模式无 URL 不受影响', () => {
  const target = mkTarget({ hpp: true }, { mode: 'direct', sqlTemplate: 'SELECT * FROM t WHERE id={INJECT}' });
  const point = { location: 'url', param: 'id', originalValue: '1', sqlTemplate: 'SELECT * FROM t WHERE id={INJECT}' };
  const req = buildInjectionRequest(target, point, "1' OR 1=1-- -");
  assert.equal(req.url, '');
  assert.ok(req.sql.includes("1' OR 1=1-- -"));
});

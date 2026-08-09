import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest } from '../src/engine/injection.js';

const target = {
  method: 'GET',
  baseUrl: 'http://t/vuln?q=1&id=5',
  headerParams: {},
  cookieParams: {},
};

const point = { location: 'url', param: 'q', originalValue: '1' };
const value = "1' AND 1=1-- -";

test('未开 hpp → URL 注入点参数单值 set（原样覆盖）', () => {
  const ctx = { config: { hpp: false } };
  const req = buildInjectionRequest(target, point, value, ctx);
  const u = new URL(req.url);
  // 单值，且其他参数 id=5 保留
  assert.equal(u.searchParams.get('q'), value);
  assert.equal(u.searchParams.get('id'), '5');
  // 没有同名多值
  assert.equal(u.searchParams.getAll('q').length, 1);
});

test('开启 hpp → URL 注入点展开同名多值（orig 在前、注入在末），其他参数保留', () => {
  const ctx = { config: { hpp: true } };
  const req = buildInjectionRequest(target, point, value, ctx);
  const u = new URL(req.url);
  const all = u.searchParams.getAll('q');
  assert.equal(all.length, 2, '应展开为同名两个值');
  assert.equal(all[0], '1', '首值应为原始合法值（绕过 WAF 首值检查）');
  assert.equal(all[1], value, '末值应为注入值（后端取末值/拼接执行）');
  // 其他参数不受影响
  assert.equal(u.searchParams.get('id'), '5');
});

test('开启 hpp → 原始 URL 无该参数时，首值退化用 originalValue', () => {
  const t2 = { ...target, baseUrl: 'http://t/vuln?id=5' };
  const ctx = { config: { hpp: true } };
  const req = buildInjectionRequest(t2, point, value, ctx);
  const u = new URL(req.url);
  const all = u.searchParams.getAll('q');
  assert.equal(all.length, 2);
  assert.equal(all[0], '1'); // originalValue
  assert.equal(all[1], value);
});

test('开启 hpp → 仅影响 url 注入点，body/cookie/header 不受影响（单值）', () => {
  const ctx = { config: { hpp: true } };
  // body 点
  const bodyPoint = { location: 'body', param: 'q', originalValue: '1', formValues: {} };
  const bodyReq = buildInjectionRequest(target, bodyPoint, value, ctx);
  assert.equal(bodyReq.data['q'], value);
  assert.ok(!Array.isArray(bodyReq.data['q']));
  // cookie 点
  const cookiePoint = { location: 'cookie', param: 'q', originalValue: '1' };
  const cookieReq = buildInjectionRequest(target, cookiePoint, value, ctx);
  assert.match(cookieReq.headers['Cookie'], new RegExp(`q=${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  // header 点
  const headerPoint = { location: 'header', param: 'X-Q', originalValue: '1' };
  const headerReq = buildInjectionRequest(target, headerPoint, value, ctx);
  assert.equal(headerReq.headers['X-Q'], value);
});

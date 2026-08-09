// 注入边界（--prefix/--suffix，sqlmap 风格）回归测试
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyBoundary, buildInjectionRequest } from '../src/engine/injection.js';
import { Detector } from '../src/engine/Detector.js';

const point = { location: 'url', param: 'id', originalValue: '1' };
const target = { method: 'GET', baseUrl: 'http://t/v.php', headerParams: {} };

test('applyBoundary：无边界配置 → 原样返回', () => {
  assert.equal(applyBoundary('1 UNION SELECT 1', point, null), '1 UNION SELECT 1');
  assert.equal(applyBoundary('1 UNION SELECT 1', point, {}), '1 UNION SELECT 1');
});

test('applyBoundary：value 以原始值开头 → prefix 精确插入其后、suffix 追加末尾', () => {
  // orig='1', value='1 UNION SELECT 1', prefix=')', suffix='-- -'
  const out = applyBoundary('1 UNION SELECT 1', point, { prefix: ')', suffix: '-- -' });
  assert.equal(out, '1) UNION SELECT 1-- -');
});

test('applyBoundary：仅 suffix → 仅末尾追加', () => {
  const out = applyBoundary('1 UNION SELECT 1', point, { suffix: '#' });
  assert.equal(out, '1 UNION SELECT 1#');
});

test('applyBoundary：value 不以原始值开头 → 整体包裹 prefix+value+suffix', () => {
  const out = applyBoundary("1' AND 1=1", point, { prefix: "'", suffix: '-- -' });
  assert.equal(out, "1'' AND 1=1-- -");
});

test('buildInjectionRequest：经 ctx.config.injectionBoundary 套用到 url 参数', () => {
  const ctx = { config: { injectionBoundary: { prefix: ')', suffix: '-- -' } } };
  const req = buildInjectionRequest(target, point, '1 UNION SELECT 1', ctx);
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1) UNION SELECT 1-- -');
});

test('buildInjectionRequest：无 ctx → 不套边界（基线兼容）', () => {
  const req = buildInjectionRequest(target, point, '1 UNION SELECT 1');
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1 UNION SELECT 1');
});

test('Detector.buildRequest：target.config.injectionBoundary 覆盖全部检测技术', () => {
  const t = { ...target, config: { injectionBoundary: { prefix: ')', suffix: '-- -' } } };
  const req = new Detector('union').buildRequest(t, point, '1 UNION SELECT 1');
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1) UNION SELECT 1-- -');
});

test('Detector.buildRequest：无 injectionBoundary → 原样', () => {
  const t = { ...target, config: {} };
  const req = new Detector('boolean').buildRequest(t, point, '1 AND 1=1');
  const u = new URL(req.url);
  assert.equal(u.searchParams.get('id'), '1 AND 1=1');
});

test('body 注入点：边界同样套用', () => {
  const p = { location: 'body', param: 'id', originalValue: '1', formValues: {} };
  const t = { ...target, config: { injectionBoundary: { prefix: ')', suffix: '-- -' } } };
  const req = new Detector('union').buildRequest(t, p, '1 UNION SELECT 1');
  assert.equal(req.data.id, '1) UNION SELECT 1-- -');
});

// ============================================================================
// tests/onlyPoint.retest.test.js —— 单点重测（onlyPoint）契约测试
// 背景：POST /api/scan/:id/point/:pointId/retest 与 TargetParser._applyOnlyPoint
// 此前零测试覆盖。本文件覆盖：
//   1) onlyPoint 过滤语义（location:param 匹配；location 省略时按 param 匹配）
//   2) 未匹配时报 INVALID_PARAM（含可用点位提示，不静默空扫描）
//   3) onlyPoint 未配置 → 原样返回（零回归）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { ErrorCode } from '../src/core/errors.js';

const parser = new TargetParser({ request: async () => ({ data: '', status: 200 }) });

test('onlyPoint：location+param 双匹配只保留目标点', () => {
  const points = [
    { id: 'a', location: 'url', param: 'id' },
    { id: 'b', location: 'url', param: 'q' },
    { id: 'c', location: 'body', param: 'id' },
  ];
  const out = parser._applyOnlyPoint(points, { onlyPoint: { location: 'url', param: 'id' } });
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'a');
});

test('onlyPoint：location 省略时按 param 跨位置匹配（同名参数多位置全保留）', () => {
  const points = [
    { id: 'a', location: 'url', param: 'id' },
    { id: 'c', location: 'body', param: 'id' },
    { id: 'b', location: 'url', param: 'q' },
  ];
  const out = parser._applyOnlyPoint(points, { onlyPoint: { param: 'id' } });
  assert.equal(out.length, 2);
  assert.ok(out.every((p) => p.param === 'id'));
});

test('onlyPoint：未匹配报 INVALID_PARAM 并列出可用点位（不静默空扫描）', () => {
  const points = [{ id: 'a', location: 'url', param: 'id' }];
  assert.throws(
    () => parser._applyOnlyPoint(points, { onlyPoint: { location: 'url', param: 'nope' } }),
    (e) => e instanceof Error && e.code === ErrorCode.INVALID_PARAM && /url:id/.test(e.message)
  );
});

test('onlyPoint：未配置 → 原样返回（零回归）', () => {
  const points = [{ id: 'a' }, { id: 'b' }];
  assert.equal(parser._applyOnlyPoint(points, {}), points);
  assert.equal(parser._applyOnlyPoint(points, { onlyPoint: null }), points);
  assert.equal(parser._applyOnlyPoint(points, { onlyPoint: { param: '' } }), points);
});

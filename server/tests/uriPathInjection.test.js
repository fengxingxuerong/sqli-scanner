// URI 路径注入点（P3）：URL 路径含 * 标记路径段注入位置
// 覆盖：路径注入点发现 / buildInjectionRequest 路径替换 / * 优先级（路径 * 优先于参数值尾 *）/ P1-U4 回归
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { createTarget } from '../src/engine/models.js';

const parser = new TargetParser();

// ===== 路径注入点发现 =====
test('discover：URL 路径含 * 识别路径段注入点', async () => {
  const target = createTarget({ url: 'http://host/api/v1/users/1*/profile' });
  const points = await parser.discover(target);
  assert.equal(points.length, 1);
  const p = points[0];
  assert.equal(p.location, 'path');
  assert.equal(p.originalValue, '1');
  assert.equal(p.pathSegment, 4); // ['', 'api', 'v1', 'users', '1*', 'profile'] → 下标 4
  assert.equal(p.precisionMarked, true);
});

test('discover：多个路径 * 段全部保留为注入点', async () => {
  const target = createTarget({ url: 'http://host/a*/b*/c' });
  const points = await parser.discover(target);
  assert.equal(points.length, 2);
  assert.deepEqual(points.map((p) => p.pathSegment).sort(), [1, 2]);
  assert.deepEqual(points.map((p) => p.originalValue).sort(), ['a', 'b']);
  assert.ok(points.every((p) => p.location === 'path'));
});

test('discover：路径 * 优先于参数值尾 *（P1-U4 逻辑不被误触发）', async () => {
  const target = createTarget({ url: 'http://host/api/u/1*/x?id=5*&name=foo' });
  const points = await parser.discover(target);
  // 路径命中 * → 只返回路径点，查询参数（含值尾 *）不再参与
  assert.equal(points.length, 1);
  assert.equal(points[0].location, 'path');
  assert.equal(points[0].originalValue, '1');
});

test('discover：仅参数值尾 *（无路径 *）仍走 P1-U4 精确标记（回归）', async () => {
  const target = createTarget({ url: 'http://host/page?id=1*&name=x' });
  const points = await parser.discover(target);
  assert.equal(points.length, 1);
  assert.equal(points[0].location, 'url');
  assert.equal(points[0].param, 'id');
  assert.equal(points[0].originalValue, '1');
  assert.equal(points[0].precisionMarked, true);
});

// ===== buildInjectionRequest 路径替换 =====
test('buildInjectionRequest：path 位置替换 URL 路径标记段', async () => {
  const target = createTarget({ url: 'http://host/api/v1/users/1*/profile' });
  const points = await parser.discover(target);
  const req = buildInjectionRequest(target, points[0], "1' OR '1'='1");
  const u = new URL(req.url);
  assert.equal(u.pathname, "/api/v1/users/1'%20OR%20'1'='1/profile");
  assert.equal(u.search, ''); // 查询串保持不变
});

test('buildInjectionRequest：path 位置可回退到按 param 段值定位（无 pathSegment 时）', async () => {
  const target = createTarget({ url: 'http://host/api/users/42*' });
  const point = { location: 'path', param: '42', originalValue: '42', precisionMarked: true }; // 模拟无 pathSegment
  const req = buildInjectionRequest(target, point, '43');
  assert.equal(new URL(req.url).pathname, '/api/users/43');
});

// ===== 与检测器集成（Detector.buildRequest 经 buildInjectionRequest 生效）=====
test('path 注入点经 Detector.buildRequest 正常构造请求', async () => {
  const { Detector } = await import('../src/engine/Detector.js');
  const target = createTarget({ url: 'http://host/api/users/7*/posts' });
  const points = await parser.discover(target);
  const req = new Detector('boolean').buildRequest(target, points[0], '8');
  assert.equal(new URL(req.url).pathname, '/api/users/8/posts');
});

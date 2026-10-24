// --test-headers / --test-path 注入点发现与请求构造 单测
// 背景（2026-09-10 独立红队评测暴露）：URL 无 query 参数时（RESTful path、仅 Header 传参）
// 引擎解析出 0 个注入点却静默输出「Low 风险」，属最危险的假阴性。
// 本文件覆盖：header / cookie / path 三类注入点的发现门槛（level 与显式开关）、
// 静态资源与空段边界、以及请求构造（只替换目标段/头，不污染其余部分）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';
import { buildInjectionRequest } from '../src/engine/injection.js';

const parser = new TargetParser();

// ===== 请求头注入点 =====

test('level 3：headerParams 中的非敏感头生成 header 注入点', async () => {
  const target = createTarget({
    url: 'http://example.com/api',
    headerParams: { 'x-trace-id': 'abc' },
    config: { level: 3 },
  });
  const points = await parser.discover(target);
  const p = points.find((x) => x.location === 'header' && x.param === 'x-trace-id');
  assert.ok(p, 'level 3 应生成 header 注入点');
  assert.equal(p.originalValue, 'abc');
});

test('level 3：x-forwarded-for 属敏感头默认排除，--test-headers 显式开启时纳入', async () => {
  const mk = (config) => createTarget({
    url: 'http://example.com/api',
    headerParams: { 'x-forwarded-for': '1.2.3.4' },
    config,
  });
  const without = await parser.discover(mk({ level: 3 }));
  assert.equal(
    without.filter((p) => p.location === 'header').length, 0,
    'level 3 未显式开启时不应测试 x-forwarded-for'
  );
  const withFlag = await parser.discover(mk({ level: 1, testHeaders: true }));
  const p = withFlag.find((x) => x.location === 'header' && x.param === 'x-forwarded-for');
  assert.ok(p, '--test-headers 应绕过敏感头过滤（level 1 亦生效）');
  assert.equal(p.originalValue, '1.2.3.4');
});

test('level 1 且未开启 --test-headers：不生成任何 header 注入点（零回归）', async () => {
  const target = createTarget({
    url: 'http://example.com/api',
    headerParams: { 'x-trace-id': 'abc' },
    config: { level: 1 },
  });
  const points = await parser.discover(target);
  assert.equal(points.filter((p) => p.location === 'header').length, 0);
});

test('请求头注入构造：写入对应头且不污染其他头', () => {
  const target = createTarget({
    url: 'http://example.com/api',
    headerParams: { 'x-trace-id': 'abc', 'x-keep': 'keep' },
    config: { level: 3 },
  });
  const point = { location: 'header', param: 'x-trace-id', originalValue: 'abc' };
  const req = buildInjectionRequest(target, point, "1' AND SLEEP(1)-- -");
  assert.equal(req.headers['x-trace-id'], "1' AND SLEEP(1)-- -");
  assert.equal(req.headers['x-keep'], 'keep', '非注入头应保持原值');
});

// ===== Cookie 注入点 =====

test('Cookie 注入点：level 1 不生成，level 2 生成', async () => {
  const mk = (level) => createTarget({
    url: 'http://example.com/api',
    cookieParams: { uid: '1' },
    config: { level },
  });
  assert.equal((await parser.discover(mk(1))).filter((p) => p.location === 'cookie').length, 0);
  const pts = await parser.discover(mk(2));
  const p = pts.find((x) => x.location === 'cookie');
  assert.ok(p, 'level 2 应生成 cookie 注入点');
  assert.equal(p.param, 'uid');
});

// ===== path 注入点 =====

test('--test-path：URL 末段生成 path 注入点并记录段下标', async () => {
  const target = createTarget({ url: 'http://example.com/api/order/1024', config: { testPath: true } });
  const points = await parser.discover(target);
  const p = points.find((x) => x.location === 'path');
  assert.ok(p, '应生成 path 注入点');
  assert.equal(p.param, '1024');
  assert.equal(p.originalValue, '1024');
  assert.equal(typeof p.pathSegment, 'number', '应记录 pathSegment 下标供精确替换');
});

test('--test-path 默认关闭（零回归）', async () => {
  const target = createTarget({ url: 'http://example.com/api/order/1024' });
  const points = await parser.discover(target);
  assert.equal(points.filter((p) => p.location === 'path').length, 0);
});

test('--test-path：静态资源末段跳过', async () => {
  for (const u of ['http://example.com/index.html', 'http://example.com/a/app.js', 'http://example.com/logo.png']) {
    const target = createTarget({ url: u, config: { testPath: true } });
    const points = await parser.discover(target);
    assert.equal(points.filter((p) => p.location === 'path').length, 0, `${u} 不应生成 path 注入点`);
  }
});

test('--test-path：末段为空（尾斜杠）时回退到最后一个有效段', async () => {
  const target = createTarget({ url: 'http://example.com/api/order/1024/', config: { testPath: true } });
  const points = await parser.discover(target);
  const p = points.find((x) => x.location === 'path');
  assert.ok(p, '尾斜杠不应导致漏掉 path 点');
  assert.equal(p.originalValue, '1024');
});

test('path 注入构造：只替换目标段，保留其余路径段与 query', () => {
  const base = 'http://example.com/api/order/1024?trace=1';
  const target = createTarget({ url: base, config: { testPath: true } });
  const point = { location: 'path', param: '1024', originalValue: '1024', pathSegment: 3 };
  const req = buildInjectionRequest(target, point, "1' AND 1=1-- -");
  const u = new URL(req.url);
  assert.equal(u.pathname.split('/')[1], 'api', '前段路径不应被破坏');
  assert.equal(u.pathname.split('/')[2], 'order', '前段路径不应被破坏');
  assert.ok(u.pathname.split('/')[3].startsWith('1'), '末段应被替换为注入值');
  assert.equal(u.searchParams.get('trace'), '1', 'query 应保留');
});

// ===== [D154] 路径注入面扩展（多段 / 数据后缀） =====
// 背景：e2e/detect-surface-lab（真 MariaDB）实测，旧口径对以下两类载体 0 检出：
//   · /api/users/5/orders —— 只测末段，中间的数字 id 从来不是点位
//   · /api/item/5.json   —— 含点即判静态，整段跳过，一个点都不生成
// 同形态安全对照（真参数化）0 误报，所以这是漏检而不是「本来就测不到」。

test('[D154] 多段路径：中间的数字段也生成注入点（REST 最常见的 id 位置）', async () => {
  const target = createTarget({ url: 'http://example.com/api/users/5/orders', config: { testPath: true } });
  const points = await parser.discover(target);
  const ids = points.filter((p) => p.location === 'path').map((p) => p.param);
  assert.ok(ids.includes('5'), `中间段 5 应作为注入点，实际：${ids.join(',')}`);
  assert.ok(ids.includes('orders'), '末段仍应测（零回归）');
  const p5 = points.find((x) => x.location === 'path' && x.param === '5');
  assert.equal(p5.pathSegment, 3, 'pathSegment 应指向真实下标，注入才不会打错段');
});

test('[D154] 多段路径：纯路由段（api/v1/users）不生成点位（请求预算不烧在必然 404 的段上）', async () => {
  const target = createTarget({ url: 'http://example.com/api/v1/users/5/orders', config: { testPath: true } });
  const points = await parser.discover(target);
  const ids = points.filter((p) => p.location === 'path').map((p) => p.param);
  assert.deepEqual(ids.sort(), ['5', 'orders'].sort(), `实际：${ids.join(',')}`);
});

test('[D154] 数据后缀段：.json 生成点位且保留后缀，只替换前缀', async () => {
  const base = 'http://example.com/api/item/5.json';
  const target = createTarget({ url: base, config: { testPath: true } });
  const points = await parser.discover(target);
  const p = points.find((x) => x.location === 'path');
  assert.ok(p, '.json 后缀段应生成注入点（旧口径被当静态资源整段跳过）');
  assert.equal(p.param, '5', 'param 应是后缀前缀，不是整段');
  assert.equal(p.pathSuffix, '.json', '后缀必须记录，注入时原样保留');
  const req = buildInjectionRequest(target, p, "1' AND 1=1-- -");
  const u = new URL(req.url);
  assert.ok(
    u.pathname.endsWith(".json"),
    `注入段必须保留 .json 后缀（去掉即 404，注入值不会进业务逻辑），实际：${u.pathname}`
  );
  assert.ok(u.pathname.includes("1'"), '前缀应被替换为注入值');
});

test('[D154] 数据后缀安全对照：静态资源与未知后缀仍然跳过（不制造噪声点位）', async () => {
  for (const u of ['http://example.com/a/app.js', 'http://example.com/index.html', 'http://example.com/v1.2']) {
    const points = await parser.discover(createTarget({ url: u, config: { testPath: true } }));
    assert.equal(points.filter((p) => p.location === 'path').length, 0, `${u} 不应生成 path 注入点`);
  }
});

test('[D154] 精确指定注入段仍走既有 `*` 标记（P3 短路优先，不与新口径重复出点）', async () => {
  const target = createTarget({ url: 'http://example.com/api/user/alice*/orders', config: { testPath: true } });
  const points = await parser.discover(target);
  const paths = points.filter((p) => p.location === 'path');
  assert.equal(paths.length, 1, '`*` 标记只出 1 个点（整段精确指定）');
  assert.equal(paths[0].param, 'alice');
  assert.equal(paths[0].precisionMarked, true);
});

test('[D154] 路径点上限：最多 6 个（--test-path 是 opt-in 也不能无界放大请求量）', async () => {
  const target = createTarget({
    url: 'http://example.com/a1/b2/c3/d4/e5/f6/g7/h8/orders',
    config: { testPath: true },
  });
  const points = await parser.discover(target);
  assert.ok(points.filter((p) => p.location === 'path').length <= 6, '路径点数应受上限约束');
});

// ===== 空注入点告警（防静默假阴性） =====

test('无 query / 无 header / 未开 testPath：解析出 0 个注入点', async () => {
  const target = createTarget({ url: 'http://example.com/api/order/1024', config: { level: 3 } });
  const points = await parser.discover(target);
  assert.equal(points.length, 0, '这是会被上层标记为 noInjectionPoints 的场景（此前静默输出 Low）');
});

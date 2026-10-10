// [D41 2026-10-11 对标 sqlmap] 注入点筛选三件套（-p/--param-exclude/--param-filter）单测
// 覆盖三层：paramSelection 纯函数归一化 → TargetParser 收口（含筛光硬拒）→ CLI/REST 两侧接线。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';
import { AppError, ErrorCode } from '../src/core/errors.js';
import {
  normalizeParamFilter,
  normalizeTestParameter,
  applyParamSelection,
  PARAM_FILTER_PLACES,
} from '../src/engine/paramSelection.js';
import { parseArgs, buildConfig } from '../bin/cli.js';
import { guardScalarsCore } from '../src/api/scanGuard/scalarsCore.js';
import { defaults } from '../src/config/defaults.js';

const parser = new TargetParser();

const multiTarget = (config) =>
  createTarget({
    url: 'http://example.com/page?id=1&name=foo&session=abc',
    method: 'POST',
    bodyParams: { user: 'admin', note: 'hi' },
    config: { level: 2, ...config },
  });

// ===== normalizeParamFilter =====
test('normalizeParamFilter：别名归一到规范 location', () => {
  assert.deepEqual(normalizeParamFilter('get,post'), ['url', 'body']);
  assert.deepEqual(normalizeParamFilter('query'), ['url']);
  assert.deepEqual(normalizeParamFilter('URI'), ['url']);
  assert.deepEqual(normalizeParamFilter('headers,cookies'), ['header', 'cookie']);
  assert.deepEqual(normalizeParamFilter(['url', 'path']), ['url', 'path']);
  // 去重
  assert.deepEqual(normalizeParamFilter('body,POST,form'), ['body']);
});

test('normalizeParamFilter：未知位置硬拒并列出白名单', () => {
  assert.throws(
    () => normalizeParamFilter('url,websocket'),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM && e.message.includes(PARAM_FILTER_PLACES)
  );
});

test('normalizeParamFilter：空值返回 null（未配置，零行为变化）', () => {
  assert.equal(normalizeParamFilter(undefined), null);
  assert.equal(normalizeParamFilter(''), null);
  assert.equal(normalizeParamFilter([]), null);
});

// ===== normalizeTestParameter =====
test('normalizeTestParameter：逗号串→数组，保留原样大小写，clamp 32', () => {
  assert.deepEqual(normalizeTestParameter('Id, name'), ['Id', 'name']);
  assert.deepEqual(normalizeTestParameter(['a', 'b']), ['a', 'b']);
  assert.equal(normalizeTestParameter(',,,,', ), null);
  assert.equal(normalizeTestParameter(' , '), null);
  const big = Array.from({ length: 40 }, (_, i) => `p${i}`).join(',');
  assert.equal(normalizeTestParameter(big).length, 32);
});

// ===== applyParamSelection（TargetParser 收口） =====
test('testParameter：只保留指定参数（大小写不敏感），其余位置混排也能命中', async () => {
  const points = await parser.discover(multiTarget({ testParameter: ['NAME'] }));
  assert.deepEqual(points.map((p) => p.param), ['name']);
  assert.equal(points[0].location, 'url');
});

test('testParameter：跨位置同名参数一并保留（url+body 各一个 user）', async () => {
  const target = createTarget({
    url: 'http://example.com/page?user=1&id=2',
    method: 'POST',
    bodyParams: { user: 'x', pass: 'y' },
  });
  const points = await parser.discover(target, undefined, );
  // 前置：无筛选时 4 个点
  assert.equal(points.length, 4);
  const filtered = applyParamSelection(structuredClone(points), { testParameter: ['user'] });
  assert.deepEqual(filtered.map((p) => `${p.location}:${p.param}`), ['url:user', 'body:user']);
});

test('testParameter：一个都没匹配 → INVALID_PARAM 且列出可用点位', async () => {
  await assert.rejects(
    () => parser.discover(multiTarget({ testParameter: ['nope'] })),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM && e.message.includes('url:id')
  );
});

test('paramExclude：正则大小写不敏感排除；排除到 0 点 → INVALID_PARAM', async () => {
  const points = await parser.discover(multiTarget({ paramExclude: '^(ses|id)' }));
  assert.deepEqual(points.map((p) => p.param).sort(), ['name', 'note', 'user']);
  await assert.rejects(
    () => parser.discover(multiTarget({ paramExclude: '.' })),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM
  );
});

test('paramExclude：非法正则 → INVALID_PARAM（不静默忽略）', async () => {
  await assert.rejects(
    () => parser.discover(multiTarget({ paramExclude: '([' })),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM && e.message.includes('正则')
  );
});

test('paramFilter：按位置筛选（REST 数组口径 + 别名字符串口径）', async () => {
  const bodyOnly = await parser.discover(multiTarget({ paramFilter: ['body'] }));
  assert.ok(bodyOnly.length > 0);
  assert.ok(bodyOnly.every((p) => p.location === 'body'));
  const urlOnly = await parser.discover(multiTarget({ paramFilter: 'get' }));
  assert.ok(urlOnly.every((p) => p.location === 'url'));
});

test('paramFilter：位置无匹配 → INVALID_PARAM', async () => {
  await assert.rejects(
    () => parser.discover(multiTarget({ paramFilter: ['path'] })),
    (e) => e instanceof AppError && e.code === ErrorCode.INVALID_PARAM
  );
});

test('筛选链顺序：paramFilter → testParameter → paramExclude 逐级收窄', () => {
  const points = [
    { location: 'url', param: 'id' },
    { location: 'body', param: 'id' },
    { location: 'body', param: 'session' },
    { location: 'cookie', param: 'session' },
  ];
  const out = applyParamSelection(structuredClone(points), {
    paramFilter: ['body'],
    testParameter: ['id', 'session'],
    paramExclude: 'ses',
  });
  assert.deepEqual(out.map((p) => `${p.location}:${p.param}`), ['body:id']);
});

test('未配置任何筛选 → 原数组返回（零行为变化）', () => {
  const points = [{ location: 'url', param: 'id' }];
  assert.equal(applyParamSelection(points, {}), points);
  assert.equal(applyParamSelection(points, undefined), points);
});

// ===== CLI 接线 =====
test('CLI：-p/--test-param、--param-exclude、--param-filter → config 三键', () => {
  const args = parseArgs(['-p', 'id,name', '--param-exclude', 'ses|csrf', '--param-filter', 'get,post']);
  const config = buildConfig(args);
  assert.deepEqual(config.testParameter, ['id', 'name']);
  assert.equal(config.paramExclude, 'ses|csrf');
  assert.equal(config.paramFilter, 'get,post');
});

test('CLI：--retries / --http-timeout 接线既有键（含 clamp）', () => {
  const config = buildConfig(parseArgs(['--retries', '4', '--http-timeout', '8000']));
  assert.equal(config.retry, 4);
  assert.equal(config.timeoutMs, 8000);
  const clamped = buildConfig(parseArgs(['--retries', '99', '--http-timeout', '1']));
  assert.equal(clamped.retry, 5);
  assert.equal(clamped.timeoutMs, 1000);
});

test('CLI：--skip 不配 --csrf-url 也生效（D41 回归钉：曾嵌在 csrfUrl 块内静默失效）', () => {
  const config = buildConfig(parseArgs(['-u', 'http://example.com/?id=1', '--skip', 'session,csrf']));
  assert.deepEqual(config.skipParams, ['session', 'csrf']);
});

// ===== REST 白名单（scalarsCore） =====
test('REST guard：testParameter/paramExclude/paramFilter 归一化透传', () => {
  const config = {};
  guardScalarsCore(config, {
    testParameter: ['id', ' name ', ''],
    paramExclude: 'x'.repeat(300),
    paramFilter: 'get,post',
  }, {});
  assert.deepEqual(config.testParameter, ['id', 'name']);
  assert.equal(config.paramExclude.length, 200);
  assert.deepEqual(config.paramFilter, ['url', 'body']);
});

test('REST guard：paramFilter 未知位置 → 丢弃并告警（不写 config）；junk 数组 → 不写', () => {
  const config = {};
  guardScalarsCore(config, { paramFilter: ['websocket'] }, {});
  assert.equal(config.paramFilter, undefined);
  const config2 = {};
  guardScalarsCore(config2, { testParameter: 'not-an-array-but-string' }, {});
  assert.deepEqual(config2.testParameter, ['not-an-array-but-string']);
  const config3 = {};
  guardScalarsCore(config3, { testParameter: [] }, {});
  assert.equal(config3.testParameter, undefined);
});

test('REST guard：defaults 全量过闸（默认值必须能被入口校验接受 —— TODO #9 口径）', () => {
  const config = {};
  guardScalarsCore(config, defaults, {});
  // 空默认不写 config（与 skipParams 同口径：非空才收，缺省由 defaults 浅合并兜底），
  // 这条断言钉的是「过闸不炸」而不是「写入」。
  assert.equal(config.testParameter, undefined);
  assert.equal(config.paramExclude, undefined);
  assert.equal(config.paramFilter, undefined);
});

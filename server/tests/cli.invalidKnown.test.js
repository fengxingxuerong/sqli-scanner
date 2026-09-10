// [P0 2026-09-09 实战批次] CLI 新参数：--invalid-bignum/--invalid-logical/--invalid-string + --known-point
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildConfig } from '../bin/cli.js';

test('CLI：--invalid-* 映射 config.invalidValue（互斥，后不覆盖前）', () => {
  assert.equal(buildConfig(parseArgs(['-u', 'http://x/?id=1', '--invalid-bignum'])).invalidValue, 'bignum');
  assert.equal(buildConfig(parseArgs(['-u', 'http://x/?id=1', '--invalid-logical'])).invalidValue, 'logical');
  assert.equal(buildConfig(parseArgs(['-u', 'http://x/?id=1', '--invalid-string'])).invalidValue, 'string');
  // 未指定：键不存在（引擎默认 null，零回归）
  assert.equal(buildConfig(parseArgs(['-u', 'http://x/?id=1'])).invalidValue, undefined);
});

test('CLI：--known-point 解析 param/quote/paren/techniques（键值对用 ; 分隔）', () => {
  const cfg = buildConfig(parseArgs([
    '-u', 'http://x/?id=1',
    '--known-point', "param=id;quote=';paren=);techniques=union,error",
  ]));
  assert.equal(cfg.knownPoint.param, 'id');
  assert.equal(cfg.knownPoint.quote, "'");
  assert.equal(cfg.knownPoint.paren, ')');
  assert.deepEqual(cfg.knownPoint.techniques, ['union', 'error']);
});

test('CLI：--known-point 缺 param → 忽略且不产生半残配置', () => {
  const cfg = buildConfig(parseArgs(['-u', 'http://x/?id=1', '--known-point', "quote='"]));
  assert.equal(cfg.knownPoint, undefined);
  // 非法技术名被过滤后 techniques 为空 → 不写 techniques 键
  const cfg2 = buildConfig(parseArgs(['-u', 'http://x/?id=1', '--known-point', 'param=id;techniques=zzz']));
  assert.equal(cfg2.knownPoint.param, 'id');
  assert.equal(cfg2.knownPoint.techniques, undefined);
});

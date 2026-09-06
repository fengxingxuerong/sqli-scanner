// [P2-5] 协议参数三件套 --force-ssl / --ignore-redirects / --hpp：
//   parseArgs 解析为布尔开关，buildConfig 透传 config.forceSsl/ignoreRedirects/hpp。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildConfig } from '../bin/cli.js';

// ─────────────── parseArgs ───────────────
test('parseArgs: --force-ssl 解析为布尔 true', () => {
  const a = parseArgs(['-u', 'http://x', '--force-ssl']);
  assert.equal(a.forceSsl, true);
});

test('parseArgs: --ignore-redirects 解析为布尔 true', () => {
  const a = parseArgs(['-u', 'http://x', '--ignore-redirects']);
  assert.equal(a.ignoreRedirects, true);
});

test('parseArgs: --hpp 解析为布尔 true', () => {
  const a = parseArgs(['-u', 'http://x', '--hpp']);
  assert.equal(a.hpp, true);
});

test('parseArgs: 不带协议开关时默认 false（回归护栏）', () => {
  const a = parseArgs(['-u', 'http://x']);
  assert.equal(a.forceSsl, false);
  assert.equal(a.ignoreRedirects, false);
  assert.equal(a.hpp, false);
});

test('parseArgs: 三开关共存且不吞后续参数', () => {
  const a = parseArgs(['-u', 'http://x', '--force-ssl', '--ignore-redirects', '--hpp', '--dbs']);
  assert.equal(a.forceSsl, true);
  assert.equal(a.ignoreRedirects, true);
  assert.equal(a.hpp, true);
  assert.equal(a.dbs, true);
});

// ─────────────── buildConfig ───────────────
test('buildConfig: --force-ssl 透传 config.forceSsl=true', () => {
  const cfg = buildConfig(parseArgs(['-u', 'http://x/?id=1', '--force-ssl']));
  assert.equal(cfg.forceSsl, true);
});

test('buildConfig: --ignore-redirects 透传 config.ignoreRedirects=true', () => {
  const cfg = buildConfig(parseArgs(['-u', 'http://x/?id=1', '--ignore-redirects']));
  assert.equal(cfg.ignoreRedirects, true);
});

test('buildConfig: --hpp 透传 config.hpp=true', () => {
  const cfg = buildConfig(parseArgs(['-u', 'http://x/?id=1', '--hpp']));
  assert.equal(cfg.hpp, true);
});

test('buildConfig: 未开启时 config 不含协议键或为 false（回归护栏）', () => {
  const cfg = buildConfig(parseArgs(['-u', 'http://x/?id=1']));
  assert.ok(!cfg.forceSsl && !cfg.ignoreRedirects && !cfg.hpp, '默认应全部关闭');
});

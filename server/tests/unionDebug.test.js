// unionDebug —— UNION 链路诊断开关的回归
// 背景：2026-09-09 定位「CRS 下 union 技术位恒 0」全靠临时插桩 print，
// 事后把开关固化成 unionDebug.js，这里锁住「默认静默 / 开启才输出」两条边界。
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { unionDebug, unionDebugEnabled } from '../src/engine/unionDebug.js';

let origEnv;
let origError;
let lines;

beforeEach(() => {
  origEnv = process.env.SQLI_UNION_DEBUG;
  origError = console.error;
  lines = [];
  console.error = (m) => lines.push(String(m));
});

afterEach(() => {
  process.env.SQLI_UNION_DEBUG = origEnv;
  if (origEnv === undefined) delete process.env.SQLI_UNION_DEBUG;
  console.error = origError;
});

test('unionDebug：默认（未设环境变量）完全静默，不写 stderr', () => {
  delete process.env.SQLI_UNION_DEBUG;
  assert.equal(unionDebugEnabled(), false);
  unionDebug('should not appear');
  assert.deepEqual(lines, []);
});

test('unionDebug：SQLI_UNION_DEBUG=1 时输出且带 [union-debug] 前缀', () => {
  process.env.SQLI_UNION_DEBUG = '1';
  assert.equal(unionDebugEnabled(), true);
  unionDebug('gate pass=false');
  assert.equal(lines.length, 1);
  assert.equal(lines[0], '[union-debug] gate pass=false');
});

test('unionDebug：环境变量在 import 之后设置也能生效（惰性读取）', () => {
  process.env.SQLI_UNION_DEBUG = 'true';
  assert.equal(unionDebugEnabled(), true);
  process.env.SQLI_UNION_DEBUG = '0';
  assert.equal(unionDebugEnabled(), false);
  unionDebug('muted');
  assert.deepEqual(lines, []);
});

test('unionDebug：stderr 写入失败时不抛，诊断绝不打断扫描主链路', () => {
  process.env.SQLI_UNION_DEBUG = '1';
  console.error = () => {
    throw new Error('stderr closed');
  };
  assert.doesNotThrow(() => unionDebug('x'));
});

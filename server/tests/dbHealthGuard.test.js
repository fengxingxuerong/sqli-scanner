// dbHealthGuard.js 单元测试：致命 DB 错误识别 + 熔断状态机
// 覆盖点：
//   1) 只认「目标受损」信号，不误伤普通 SQL 报错（否则 error 技术整体失效）
//   2) 熔断后跳过重型嵌套 payload，未熔断时零行为变化（不回归既有检出率/请求数）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectFatalDbError,
  isHeavyPayload,
  DbHealthGuard,
  FATAL_DB_SIGS,
} from '../src/core/dbHealthGuard.js';

test('5xx + stack depth 判定为致命', () => {
  const hit = detectFatalDbError({ status: 500, data: '<pre>stack depth limit exceeded</pre>' });
  assert.ok(hit);
  assert.equal(hit.id, 'stack_depth');
});

test('普通 SQL 语法报错不熔断（否则 error 检测失效）', () => {
  const cases = [
    { status: 500, data: `You have an error in your SQL syntax` },
    { status: 500, data: `syntax error at or near "1"` },
    { status: 500, data: `ORA-01756: quoted string not properly terminated` },
    { status: 500, data: `Unclosed quotation mark` },
  ];
  for (const c of cases) assert.equal(detectFatalDbError(c), null, JSON.stringify(c));
});

test('2xx 页面即使含致命文案也不熔断（成功页不存在目标受损）', () => {
  assert.equal(detectFatalDbError({ status: 200, data: 'stack depth limit exceeded' }), null);
});

test('连接池耗尽 / 只读事务 / OOM 均可识别', () => {
  assert.equal(detectFatalDbError({ status: 500, data: 'FATAL: sorry, too many clients already' }).id, 'too_many_connections');
  assert.equal(detectFatalDbError({ status: 500, data: 'cannot execute INSERT in a read-only transaction' }).id, 'db_readonly');
  assert.ok(detectFatalDbError({ status: 500, data: 'out of memory' }));
});

test('空响应/无状态码不熔断', () => {
  assert.equal(detectFatalDbError(null), null);
  assert.equal(detectFatalDbError({ status: 500, data: '' }), null);
  assert.equal(detectFatalDbError({ data: 'stack depth limit exceeded' }), null);
});

test('致命特征表每项含 id 与 hint', () => {
  for (const s of FATAL_DB_SIGS) {
    assert.ok(s.id && s.hint, JSON.stringify(s));
    assert.ok(s.sig instanceof RegExp);
  }
});

test('重型 payload 判定：多层嵌套子查询', () => {
  assert.equal(isHeavyPayload("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -"), true);
  assert.equal(isHeavyPayload('1 AND 1=1'), false);
  assert.equal(isHeavyPayload("1' AND 1=CAST((SELECT current_schema) AS int)-- -"), false);
  assert.equal(isHeavyPayload('1 UNION SELECT NULL,NULL,NULL,NULL-- -'), false);
  assert.equal(isHeavyPayload(''), false);
});

test('未熔断时 shouldSkip 恒为 false（默认路径零变化）', () => {
  const g = new DbHealthGuard();
  assert.equal(g.shouldSkip("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a)x FROM t GROUP BY x)y)-- -"), false);
  assert.equal(g.tripped, false);
  assert.equal(g.skippedHeavy, 0);
});

test('熔断后跳过重型 payload，保留扁平 payload', () => {
  const tripped = [];
  const g = new DbHealthGuard({ onTrip: (i) => tripped.push(i) });
  g.observe({ status: 500, data: 'stack depth limit exceeded' });
  assert.equal(g.tripped, true);
  assert.equal(tripped.length, 1);
  assert.equal(tripped[0].id, 'stack_depth');

  const heavy = "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a)x FROM t GROUP BY x)y)-- -";
  assert.equal(g.shouldSkip(heavy), true);
  assert.equal(g.shouldSkip('1 AND 1=1'), false);
  assert.equal(g.shouldSkip("1' AND 1=CAST((SELECT 1) AS int)-- -"), false);
  assert.equal(g.skippedHeavy, 1);
});

test('shouldAbort 达到阈值才中止（默认 3 次）', () => {
  const g = new DbHealthGuard();
  const fatal = { status: 500, data: 'stack depth limit exceeded' };
  assert.equal(g.shouldAbort, false);
  g.observe(fatal);
  assert.equal(g.shouldAbort, false);
  g.observe(fatal);
  assert.equal(g.shouldAbort, false);
  g.observe(fatal);
  assert.equal(g.shouldAbort, true);
});

test('abortAfter 可配置', () => {
  const g = new DbHealthGuard({ abortAfter: 1 });
  g.observe({ status: 500, data: 'stack depth limit exceeded' });
  assert.equal(g.shouldAbort, true);
});

test('onTrip 仅首次触发；回调抛错不影响熔断状态', () => {
  let n = 0;
  const g = new DbHealthGuard({ onTrip: () => { n++; throw new Error('boom'); } });
  const fatal = { status: 500, data: 'stack depth limit exceeded' };
  g.observe(fatal);
  g.observe(fatal);
  g.observe(fatal);
  assert.equal(n, 1);
  assert.equal(g.tripped, true);
  assert.equal(g.fatalHits, 3);
});

test('summary 未熔断返回 null，熔断后含诊断信息', () => {
  const g = new DbHealthGuard();
  assert.equal(g.summary(), null);
  g.observe({ status: 500, data: 'stack depth limit exceeded' });
  const s = g.summary();
  assert.equal(s.fatalId, 'stack_depth');
  assert.equal(s.fatalHits, 1);
  assert.equal(s.aborted, false);
  assert.ok(typeof s.hint === 'string' && s.hint.length > 0);
});

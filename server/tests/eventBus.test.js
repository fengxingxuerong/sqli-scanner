// eventBus.js 单元测试：按 scanId 隔离 + 事件结构 + toSSE 未知扫描分支
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as eventBus from '../src/core/eventBus.js';

test('create 返回按 scanId 隔离的发射器', () => {
  const a = eventBus.create('scanA');
  const b = eventBus.create('scanB');
  assert.notEqual(a, b);
});

test('emit 仅触发同 scanId 的监听', () => {
  eventBus.create('scanX');
  eventBus.create('scanY');
  let xGot = 0;
  let yGot = 0;
  eventBus.create('scanX').on('event', () => xGot++);
  eventBus.create('scanY').on('event', () => yGot++);
  eventBus.emit('scanX', 'point_discovered', { n: 1 });
  assert.equal(xGot, 1);
  assert.equal(yGot, 0);
});

test('emit 包装事件结构 {type, scanId, ts, payload}', () => {
  eventBus.create('scanZ');
  let evt = null;
  eventBus.create('scanZ').on('event', (e) => (evt = e));
  eventBus.emit('scanZ', 'scan_started', { foo: 1 });
  assert.equal(evt.type, 'scan_started');
  assert.equal(evt.scanId, 'scanZ');
  assert.ok(typeof evt.ts === 'string' && evt.ts.length > 0);
  assert.deepEqual(evt.payload, { foo: 1 });
});

test('emit 未 create 的 scanId 不抛错', () => {
  assert.doesNotThrow(() => eventBus.emit('never-created', 'x', {}));
});

test('dispose 清理命名空间', () => {
  eventBus.create('scanD');
  let got = 0;
  eventBus.create('scanD').on('event', () => got++);
  eventBus.dispose('scanD');
  eventBus.emit('scanD', 'x', {});
  assert.equal(got, 0);
});

test('toSSE 对未知 scanId 立即推送 scan_error', () => {
  const writes = [];
  const res = { writeHead() {}, write: (s) => writes.push(s) };
  const req = { on() {} };
  eventBus.toSSE('unknown-scan-xyz', req, res);
  assert.ok(writes.some((w) => w.includes('scan_error')), '应推送 scan_error');
});

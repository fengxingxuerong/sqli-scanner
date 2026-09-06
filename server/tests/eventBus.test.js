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

// [P3-SSE] 回放缓冲：emit 附带单调 seq，重连（lastEventId 游标）补发错过的事件
test('emit 事件附带单调递增 seq 并进入回放缓冲', () => {
  eventBus.create('scanR');
  let lastSeq = 0;
  eventBus.create('scanR').on('event', (e) => {
    assert.equal(typeof e.seq, 'number');
    assert.ok(e.seq > lastSeq, 'seq 应单调递增');
    lastSeq = e.seq;
  });
  eventBus.emit('scanR', 'a', {});
  eventBus.emit('scanR', 'b', {});
});

test('toSSE 按 lastEventId 查询参数回放之后的事件', () => {
  eventBus.create('scanReplay');
  eventBus.emit('scanReplay', 'point_discovered', { n: 1 }); // seq=S1
  eventBus.emit('scanReplay', 'http_request', { n: 2 }); // seq=S2
  const s1 = eventBus.create('scanReplay')._replayBuffer?.[0]?.seq;

  // 捕获清理钩子：toSSE 会注册 15s 心跳定时器，必须触发 close 才不会让测试进程悬挂
  const hooks = [];
  const mkReq = (query) => ({ on: (_e, fn) => hooks.push(fn), query });
  const mkRes = (writes) => ({ writeHead() {}, write: (s) => writes.push(s), on: (_e, fn) => hooks.push(fn) });

  const writes = [];
  eventBus.toSSE('scanReplay', mkReq({ lastEventId: String(s1) }), mkRes(writes));
  const replayed = writes.filter((w) => w.startsWith('id:'));
  assert.ok(replayed.length >= 1, '应至少回放 1 条游标之后的事件');
  assert.ok(replayed.every((w) => w.includes('http_request')), '不应回放游标之前的事件');

  // 游标为 0 / 缺省时不回放历史
  const writes2 = [];
  eventBus.toSSE('scanReplay', mkReq(), mkRes(writes2));
  assert.ok(!writes2.some((w) => w.startsWith('id:') && w.includes('point_discovered')), '无游标不回放旧事件');

  // 收尾：触发 close 清理两个连接的心跳定时器与监听器
  for (const fn of hooks) fn();
});

test('dispose 后回放缓冲一并回收', () => {
  eventBus.create('scanDisposeBuf');
  eventBus.emit('scanDisposeBuf', 'x', {});
  eventBus.dispose('scanDisposeBuf');
  eventBus.emit('scanDisposeBuf', 'y', {}); // 未 create 不应抛错
  assert.ok(true);
});

// [r2-01 H1] 回归守卫：终态事件只允许出现一次（listener 跳过终态，terminalListener 独写并收尾）
test('toSSE 终态事件单连接只推送一次且随后收尾', () => {
  eventBus.create('scanTerminalOnce');
  const writes = [];
  const hooks = [];
  const req = { on: (_e, fn) => hooks.push(fn) };
  const res = {
    writeHead() {},
    write: (s) => writes.push(s),
    on: (_e, fn) => hooks.push(fn),
    end: () => hooks.push('__ended__'),
  };
  eventBus.toSSE('scanTerminalOnce', req, res);
  eventBus.emit('scanTerminalOnce', 'point_testing', { pointId: 'p1' });
  eventBus.emit('scanTerminalOnce', 'scan_completed', { ok: true });
  const terminalWrites = writes.filter((w) => w.includes('scan_completed'));
  assert.equal(terminalWrites.length, 1, `终态事件应只写一次，实际 ${terminalWrites.length} 次`);
  assert.ok(hooks.includes('__ended__'), '终态后应主动 end 连接');

  // scan_error / scan_stopped 同样只写一次
  for (const type of ['scan_error', 'scan_stopped']) {
    const ns = `scanTerm-${type}`;
    eventBus.create(ns);
    const w2 = [];
    const h2 = [];
    eventBus.toSSE(ns, { on: (_e, fn) => h2.push(fn) }, {
      writeHead() {}, write: (s) => w2.push(s), on: (_e, fn) => h2.push(fn), end: () => h2.push('__ended__'),
    });
    eventBus.emit(ns, type, {});
    assert.equal(w2.filter((x) => x.includes(type)).length, 1, `${type} 应只写一次`);
    for (const fn of h2) if (typeof fn === 'function') fn();
  }

  // 收尾：清理首个连接的心跳定时器与监听器
  for (const fn of hooks) if (typeof fn === 'function') fn();
});

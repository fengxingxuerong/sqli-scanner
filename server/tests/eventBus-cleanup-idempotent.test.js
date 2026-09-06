// SSE 清理钩子幂等闸测试（修复 P0 硬伤）
//
// 背景：eventBus.toSSE 在 req.close / res.close / res.finish 三个事件上注册
// 同一个 cleanup 函数。连接正常关闭时三个事件都会触发 → cleanup 被调用 2-3 次
// → _dec(scanId) 多次扣减 globalConnectionCount → 计数虚低 → 超限连接被误放行。
//
// 修复：加幂等闸 `if (cleaned) return`，确保同一连接的清理只执行一次。
//
// 用例：
//   1) 三个事件同时触发只清理一次（listener 被移除，后续 off 调用是 no-op）
//   2) 清理后可正常建立新连接（计数器准确，不卡死）
//   3) 单个事件触发时清理正常执行（回归守卫）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as eventBus from '../src/core/eventBus.js';

function makeMockReqRes() {
  const hooks = [];
  const writes = [];
  const req = { on: (_e, fn) => hooks.push(fn) };
  const res = {
    writeHead() {},
    write: (s) => writes.push(s),
    on: (_e, fn) => hooks.push(fn),
  };
  return { hooks, writes, req, res };
}

test('cleanup 幂等：req.close + res.close + res.finish 三次触发只执行一次清理', () => {
  const scanId = 'scanIdempotent1';
  eventBus.create(scanId);

  const { hooks, req, res } = makeMockReqRes();
  eventBus.toSSE(scanId, req, res);

  // toSSE 注册 3 个事件钩子（req close + res close + res finish）
  assert.equal(hooks.length, 3, '应注册 3 个事件钩子');

  const em = eventBus.create(scanId);
  const initialListeners = em.listenerCount('event');
  assert.ok(initialListeners >= 2, '应至少注册了 listener + terminalListener');

  // 模拟三个事件同时触发（连接正常关闭时的典型场景）
  hooks[0](); // req close
  hooks[1](); // res close
  hooks[2](); // res finish

  // 幂等闸确保：cleanup 只执行一次 → listener 被移除（不会因多次 off 出错）
  assert.equal(
    em.listenerCount('event'),
    0,
    '三次触发后 listener 应全部移除（幂等闸确保只清理一次）'
  );

  eventBus.dispose(scanId);
});

test('清理后可正常建立新连接（计数器准确，不卡死）', () => {
  const scanId = 'scanIdempotent2';
  eventBus.create(scanId);

  // 第一轮连接
  const r1 = makeMockReqRes();
  eventBus.toSSE(scanId, r1.req, r1.res);

  // 触发全部 3 个清理事件
  for (const fn of r1.hooks) fn();

  // 第二轮连接：应能正常建立（计数器准确，未被多减导致卡死）
  const r2 = makeMockReqRes();
  assert.doesNotThrow(() => eventBus.toSSE(scanId, r2.req, r2.res));

  // 第二轮连接应正常推送事件
  eventBus.create(scanId);
  eventBus.emit(scanId, 'point_discovered', { n: 1 });
  assert.ok(
    r2.writes.some((w) => w.includes('point_discovered')),
    '新连接应能正常接收事件'
  );

  // 清理第二轮
  for (const fn of r2.hooks) fn();
  eventBus.dispose(scanId);
});

test('单个事件触发时清理正常执行（回归守卫）', () => {
  const scanId = 'scanIdempotent3';
  eventBus.create(scanId);

  const { hooks, req, res } = makeMockReqRes();
  eventBus.toSSE(scanId, req, res);

  const em = eventBus.create(scanId);
  assert.ok(em.listenerCount('event') >= 2, '建立连接后应有 listener');

  // 仅触发一次（模拟只有 req close 事件）
  hooks[0]();

  assert.equal(em.listenerCount('event'), 0, '单次触发后 listener 应被移除');

  // 再次触发不应出错（幂等）
  assert.doesNotThrow(() => hooks[0]());

  eventBus.dispose(scanId);
});

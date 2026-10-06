// ============================================================================
// tests/eventBus.replayBuffer.test.js —— 回放缓冲的持有方式（2026-10-05）
//
// ── 防的是什么 ───────────────────────────────────────────────────────────────
// 回放缓冲原先是 `/** @type {any} */ (em)._replayBuffer = []` —— 把自有状态**动态挂到
// Node 内建 EventEmitter 实例上**。后果有两层：
//   ① 类型层面：写入点与读取点都要逃逸（各一处 any），且读取侧因此写成 `if (buf)`,
//      天然带着"字段可能不存在"的静默降级分支；
//   ② 更要命的是**改造时的漏改风险**：缓冲有 2 个读取点（emit 写入侧、toSSE 回放侧），
//      改表示时漏掉任何一个，回放就静默失效——表现只是"断线重连拿不到回放"，无报错。
//
// 本次改造（WeakMap）就真的漏了一次：是 grep `_replayBuffer` 才抓到 toSSE 里那处
// `em._replayBuffer || []`。若没有这道 grep，回放功能会一直坏着而测试仍绿
// （因为该分支只有 lastEventId 非空时才走到，多数测试不传它）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import * as eventBus from '../src/core/eventBus.js';

// 剥注释是源码形态判据的默认前置：本次改造的说明注释里**引用了**被禁掉的旧形态，
// 不剥就会命中自己的说明文字 ⇒ 恒红的假失败。
// （本轮第二次踩这个坑，故抽成 tests/_srcScan.mjs 共享，不再各写一遍。）
const CODE = readCode(new URL('../src/core/eventBus.js', import.meta.url));

test('形态-1) 不得再把自有状态动态挂到 emitter 实例上（any 逃逸清零）', () => {
  const dynamicMount = CODE.match(/\/\*\*\s*@type\s*\{\s*any\s*\}\s*\*\/\s*\(em\)\.\w+/g) || [];
  assert.equal(dynamicMount.length, 0,
    `仍有 ${dynamicMount.length} 处把状态动态挂到 emitter：${dynamicMount.join(' | ')}`);
});

test('形态-2) src 与测试里都不得再直接读写 _replayBuffer 字段', () => {
  assert.ok(!/\._replayBuffer/.test(CODE),
    '源码中仍有对 _replayBuffer 字段的真实访问 —— 表示已改，读取侧却漏改（回放会静默失效）');
});

test('契约-3) 回放缓冲内容可经只读访问器读取（测试不再依赖内部表示）', () => {
  const id = 'bufPeek';
  eventBus.create(id);
  eventBus.emit(id, 'point_discovered', { n: 1 });
  eventBus.emit(id, 'http_request', { n: 2 });
  const buf = eventBus._peekReplayBuffer(id);
  assert.ok(Array.isArray(buf), '应返回数组');
  assert.equal(buf.length, 2);
  assert.equal(buf[0].type, 'point_discovered');
  assert.ok(buf[0].seq < buf[1].seq, 'seq 应单调递增');
  eventBus.dispose(id);
});

test('契约-4) create 两次不丢缓冲（幂等）', () => {
  const id = 'bufIdem';
  eventBus.create(id);
  eventBus.emit(id, 'a', {});
  eventBus.create(id);
  eventBus.emit(id, 'b', {});
  assert.equal(eventBus._peekReplayBuffer(id).length, 2, '重复 create 应复用同一缓冲，不得清空');
  eventBus.dispose(id);
});

test('契约-5) dispose 后访问器返回 undefined，且不抛错', () => {
  const id = 'bufGone';
  eventBus.create(id);
  eventBus.emit(id, 'a', {});
  eventBus.dispose(id);
  assert.equal(eventBus._peekReplayBuffer(id), undefined);
  // 未 create 的命名空间同样不抛错
  assert.equal(eventBus._peekReplayBuffer('never-created-xyz'), undefined);
});

test('回归-6) 未 create 的命名空间 emit 不抛错（既有行为不得变）', () => {
  assert.doesNotThrow(() => eventBus.emit('never-created-xyz2', 'x', {}));
});

test('回归-7) 环形上限裁剪仍生效（缓冲不无界增长）', () => {
  const id = 'bufCap';
  eventBus.create(id);
  // SSE_REPLAY_MAX 默认 500，裁剪阈值 1.5×750；这里发 800 条应已被裁剪过一次
  for (let i = 0; i < 800; i++) eventBus.emit(id, 'probe', { i });
  const buf = eventBus._peekReplayBuffer(id);
  assert.ok(buf.length <= 800, `缓冲长度异常：${buf.length}`);
  assert.ok(buf.length >= 500, `缓冲被裁剪过头：${buf.length}`);
  eventBus.dispose(id);
});
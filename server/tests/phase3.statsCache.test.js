// P2-P3 chunkHashes 轻量缓存（性能）测试（node --test）
// 验证：1) 同字符串重复调用命中缓存（返回同一引用，避免重复 hash）；
//       2) 非默认块大小不误用缓存；3) chunkSimilarity 结果不变（零回归）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chunkHashes, chunkSimilarity } from '../src/core/statsHelper.js';

test('chunkHashes 同字符串缓存命中（同一引用，避免重复 hash）', () => {
  // 长串 + 首部动态内容，模拟真实响应比对场景
  const s = 'timestamp-12345|' + 'A'.repeat(500) + '|尾随内容';
  const h1 = chunkHashes(s);
  const h2 = chunkHashes(s);
  assert.equal(h1, h2, '相同输入应命中缓存并返回同一数组引用');
  assert.deepEqual(h2, h1);
  // 不同字符串不应共享缓存（引用不同，值可碰巧但引用必不同）
  const h3 = chunkHashes(s + '!');
  assert.notEqual(h1, h3);
});

test('chunkHashes 非默认块大小不误用缓存且结果正确', () => {
  const s = 'abcdefghijklmnopqrstuvwxyz';
  const a8 = chunkHashes(s, 8);
  const b8 = chunkHashes(s, 8);
  const a64 = chunkHashes(s, 64);
  assert.deepEqual(a8, b8);
  assert.equal(a8.length, Math.ceil(s.length / 8), '8 字节块应产生 ceil(len/8) 个块');
  assert.notEqual(a8.length, a64.length, '块大小不同块数不同');
});

test('chunkSimilarity 结果与缓存前后一致（零回归）', () => {
  const a = 'prefix-0001|' + 'B'.repeat(300);
  const b = 'prefix-9999|' + 'B'.repeat(300); // 仅首块不同（动态内容）
  const sim1 = chunkSimilarity(a, b);
  const sim2 = chunkSimilarity(a, b);
  assert.equal(sim2, sim1, '重复比对结果应一致（缓存不改变语义）');
  assert.ok(sim1 > 0.7, `首部动态内容场景分块相似率应较高（仅首块不同），实际 ${sim1}`);
});

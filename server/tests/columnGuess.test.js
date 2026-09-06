import { test } from 'node:test';
import assert from 'node:assert/strict';
import { binaryGuessColumns, createColumnGuessCache } from '../src/engine/columnGuess.js';

test('binaryGuessColumns：ORDER BY 1 成功 → 返回 >=1', async () => {
  const probe = async (n) => {
    if (n <= 1) return { status: 200, data: 'a'.repeat(100) };
    return { status: 500, data: '' };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 1);
});

test('binaryGuessColumns：ORDER BY maxCols+1 失败 → 实际列数 <= maxCols', async () => {
  let callCount = 0;
  const probe = async (n) => {
    callCount++;
    if (n <= 5) return { status: 200, data: 'OK'.repeat(50) };
    return { status: 500, data: '' };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 5);
  assert.ok(callCount <= 7);
});

test('缓存命中：同 cacheKey 第二次调用不发 probe 请求', async () => {
  const cache = createColumnGuessCache();
  let callCount = 0;
  const probe = async (n) => {
    callCount++;
    return { status: 200, data: 'x'.repeat(200) };
  };
  const first = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 50, cache, cacheKey: 'p1' });
  assert.ok(first >= 1);
  const firstCalls = callCount;
  const second = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 50, cache, cacheKey: 'p1' });
  assert.equal(second, first);
  assert.equal(callCount, firstCalls, '缓存命中后不应再发 probe');
});

test('失败降级：所有请求失败返回保守值 1', async () => {
  const probe = async () => null;
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50 });
  assert.equal(cols, 1);
});

test('maxColumnsGuess 参数控制上限', async () => {
  let maxProbed = 0;
  const probe = async (n) => {
    maxProbed = Math.max(maxProbed, n);
    return { status: 200, data: 'x'.repeat(200) };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 200, maxCols: 10 });
  assert.equal(cols, 10);
  assert.equal(maxProbed, 10);
});

test('createColumnGuessCache 返回新 Map', () => {
  const c = createColumnGuessCache();
  assert.ok(c instanceof Map);
  assert.equal(c.size, 0);
});
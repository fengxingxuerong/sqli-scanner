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
// [CRS-FIX 2026-09-09] 缓存投毒回归：WAF 全量拦截时每个 ORDER BY 都返回 403 短响应，
// 既非 5xx 又远短于基线 → 被判据当成「超出列数」→ 二分收敛到 1。若把该 1 写入缓存，
// 后续换用有效 tamper 链的扫描会一直复用错误列数 → UNION 永远走不通。
test('WAF 全拦（403 短响应）→ 返回保守值 1 且【不写入缓存】', async () => {
  const cache = createColumnGuessCache();
  const probe = async () => ({ status: 403, data: '<html>403 blocked</html>' }); // 长度远小于 baseLen
  const cols = await binaryGuessColumns(probe, { baseLen: 1000, maxCols: 50, cache, cacheKey: 'k1' });
  assert.equal(cols, 1, '无有效探测时应回落保守值 1');
  assert.equal(cache.has('k1'), false, '不可信结果不得写入缓存（否则污染后续扫描）');
});

test('存在 2xx 响应 → 结果可信并正常写入缓存', async () => {
  const cache = createColumnGuessCache();
  const probe = async (n) => (n <= 3 ? { status: 200, data: 'x'.repeat(100) } : { status: 500, data: '' });
  const cols = await binaryGuessColumns(probe, { baseLen: 100, maxCols: 50, cache, cacheKey: 'k2' });
  assert.equal(cols, 3);
  assert.equal(cache.get('k2'), 3, '可信结果应写入缓存');
});

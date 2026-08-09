// 二分猜列数（ORDER BY 列数枚举）回归测试
// 验证：① 返回真实列数正确；② 请求数 ≈ O(log n) 而非线性 O(n)，对齐 sqlmap。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guessColumnsBinary } from '../src/engine/injection.js';

// 构造 mock httpClient：模拟「ORDER BY n ≤ realColumns 正常、> realColumns 报错(500,短响应)」的单调信号。
// 同时统计 ORDER BY 探测次数，用于断言二分带来的请求降幅。
function makeMock(realColumns, { maxCols = 50 } = {}) {
  const calls = { orderBy: 0 };
  const httpClient = {
    request(opts) {
      // URL 中空格被编码为 '+' 或 '%20'，先解码再匹配 ORDER BY
      const url = decodeURIComponent(opts.url || '').replace(/\+/g, ' ');
      const m = url.match(/ORDER\s+BY\s+(\d+)/i);
      if (m) {
        calls.orderBy++;
        const n = Number(m[1]);
        if (n > realColumns) {
          // 超出列数：数据库报错（sqlmap 以此信号判定列数边界）
          return Promise.resolve({ status: 500, data: 'ERR', headers: {} });
        }
        return Promise.resolve({ status: 200, data: 'normal page body '.repeat(5), headers: {} });
      }
      // 基线请求（无 ORDER BY）：正常响应
      return Promise.resolve({ status: 200, data: 'normal page body '.repeat(5), headers: {} });
    },
  };
  const ctx = {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/search', headerParams: {} },
    point: { location: 'url', param: 'q', originalValue: '1' },
    config: {},
  };
  const baseLen = 'normal page body '.repeat(5).length;
  return { httpClient, ctx, baseLen, calls, maxCols };
}

test('二分猜列数：返回真实列数（多种列数）', async () => {
  for (const realColumns of [1, 2, 3, 7, 12, 25, 49, 50]) {
    const { httpClient, ctx, baseLen, maxCols } = makeMock(realColumns);
    const got = await guessColumnsBinary(httpClient, ctx, baseLen, maxCols);
    assert.equal(got, realColumns, `真实列数=${realColumns} 时应返回 ${realColumns}，实际 ${got}`);
  }
});

test('二分猜列数：真实列数超过上限时封顶到 maxCols', async () => {
  const { httpClient, ctx, baseLen, maxCols } = makeMock(100, { maxCols: 50 });
  const got = await guessColumnsBinary(httpClient, ctx, baseLen, maxCols);
  assert.equal(got, 50, `真实列数=100 > maxCols=50 时应封顶 50，实际 ${got}`);
});

test('二分猜列数：请求数 ≈ O(log n) 远低于线性 O(n)', async () => {
  // 线性扫描最坏需 maxCols 次；二分约 ⌈log2(maxCols)⌉+1 次（≤8）。
  const { httpClient, ctx, baseLen, calls, maxCols } = makeMock(37);
  const got = await guessColumnsBinary(httpClient, ctx, baseLen, maxCols);
  assert.equal(got, 37);
  assert.ok(
    calls.orderBy <= 8,
    `二分应 ≤8 次探测，实际 ${calls.orderBy} 次（线性最坏需 ${maxCols} 次）`
  );
  // 与线性最坏情况对比，降幅显著
  assert.ok(calls.orderBy < maxCols / 4, `请求数 ${calls.orderBy} 应远小于线性 ${maxCols}`);
});

test('二分猜列数：单列表（边界）正确返回 1 且探测有界', async () => {
  const { httpClient, ctx, baseLen, calls, maxCols } = makeMock(1);
  const got = await guessColumnsBinary(httpClient, ctx, baseLen, maxCols);
  assert.equal(got, 1);
  // 二分即便对单列表也需 ~⌈log2(maxCols)⌉ 次探测以排除更大列数，但有界（≤8），远低于线性 50 次
  assert.ok(calls.orderBy <= 8, `单列表二分探测应有界，实际 ${calls.orderBy} 次`);
});

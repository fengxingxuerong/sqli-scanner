// =====================================================================
// extractor.enumHelpers.test.js —— 钉住 _enumScalar / _enumList 的行为契约
//
// [为什么单独建这个文件]
// [大文件拆分 2026-09-20] 12 个枚举方法（enumerateDatabases/Tables/Columns/
// currentDb/currentUser/... ）收敛到 _enumScalar/_enumList 两个助手。
// 收敛后跑既有测试 137/137 全绿 —— 但**缺陷注入证明这不足以验证降级契约**：
// 把 `catch { return fallback }` 改成 `catch { throw }` 后，86 个 extractor 用例
// 依然全绿，说明「权限不足时静默降级」这条关键行为此前**零覆盖**。
//
// 该行为为什么要紧：枚举 information_schema 时，低权限账号会收到权限错误。
// 若此处不降级而抛错，整个扫描会在「探测能力」阶段直接中断 ——
// 而正确行为是降级为空结果、让后续 --common-tables 字典路线兜底。
//
// 本文件不 mock 网络：直接打桩 _guessColumnsCached / extractScalar 两个私有方法，
// 精确隔离被测算子。
// =====================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

const ex = new Extractor();
const ctx = { config: {} };

// 打桩两个协作方法，返回可控结果；返回 recorder 供断言调用次数
function stub({ columns = [1], scalarImpl } = {}) {
  const calls = [];
  ex._guessColumnsCached = async () => columns;
  ex.extractScalar = async (c, q, cols) => {
    calls.push({ q, cols });
    return scalarImpl ? scalarImpl(q) : 'v';
  };
  return calls;
}

// ── _enumScalar ──────────────────────────────────────────────────────

test('_enumScalar：q 为空值（null/undefined/空串）→ 直接返回 fallback，**不发请求**', async () => {
  const calls = stub();
  for (const q of [null, undefined, '']) {
    assert.equal(await ex._enumScalar(ctx, q), null, 'q falsy 应返回默认 fallback(null)');
    assert.equal(await ex._enumScalar(ctx, q, { fallback: 'x' }), 'x', '应尊重显式 fallback');
  }
  assert.equal(calls.length, 0, 'q 为空时不得调用 extractScalar');
});

test('_enumScalar：提取成功 → 返回提取值', async () => {
  const calls = stub({ scalarImpl: () => 'mysql' });
  assert.equal(await ex._enumScalar(ctx, 'SELECT database()'), 'mysql');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].cols, [1], '应把 _guessColumnsCached 的结果透传给 extractScalar');
});

test('★降级契约★ _enumScalar：extractScalar 抛错（权限不足等）→ **静默返回 fallback，不抛出**', async () => {
  stub({ scalarImpl: () => { throw new Error('SELECT command denied to user'); } });
  await assert.doesNotReject(
    () => ex._enumScalar(ctx, 'SELECT schema_name FROM information_schema.schemata'),
    '权限错误必须被吞掉：抛出会中断整个扫描'
  );
  assert.equal(await ex._enumScalar(ctx, 'x'), null, '默认 fallback 应为 null');
  assert.deepEqual(await ex._enumScalar(ctx, 'x', { fallback: [] }), [],
    '显式 fallback 为 [] 时应原样返回 []（值语义，非 null）');
  assert.equal(await ex._enumScalar(ctx, 'x', { fallback: 'n/a' }), 'n/a',
    '任意 fallback 值都应透传');
});

test('_enumScalar：fallback 为 [] 时原样返回**同一引用**（不被复制）', async () => {
  stub({ scalarImpl: () => { throw new Error('denied'); } });
  const fb = [];
  assert.equal(await ex._enumScalar(ctx, 'x', { fallback: fb }), fb);
});

// ── _enumList ────────────────────────────────────────────────────────

test('_enumList：逗号分隔值 → 切分为数组', async () => {
  stub({ scalarImpl: () => 'db1,db2,db3' });
  assert.deepEqual(await ex._enumList(ctx, 'q'), ['db1', 'db2', 'db3']);
});

test('_enumList：过滤空段（尾随逗号 / 连续逗号不产生空字符串元素）', async () => {
  stub({ scalarImpl: () => 'a,,b,' });
  assert.deepEqual(await ex._enumList(ctx, 'q'), ['a', 'b'],
    '空段必须被 filter(Boolean) 掉，否则下游会当成一个名为 "" 的库');
});

test('_enumList：q 为空 → 返回 fallback（默认 []），不发请求', async () => {
  const calls = stub();
  assert.deepEqual(await ex._enumList(ctx, null), []);
  assert.equal(calls.length, 0);
});

test('★降级契约★ _enumList：底层提取失败 → 返回**空数组**而非抛出', async () => {
  stub({ scalarImpl: () => { throw new Error('denied'); } });
  await assert.doesNotReject(() => ex._enumList(ctx, 'q'));
  assert.deepEqual(await ex._enumList(ctx, 'q'), [],
    '降级为空数组 —— 让 --common-tables 字典路线接手');
});

test('_enumList：提取值为空串/null → 返回空数组（而非 ["" ]）', async () => {
  stub({ scalarImpl: () => '' });
  assert.deepEqual(await ex._enumList(ctx, 'q'), []);
  stub({ scalarImpl: () => null });
  assert.deepEqual(await ex._enumList(ctx, 'q'), []);
});

test('_enumList：提取值非字符串（数字）→ 先 String() 再切分（既有行为）', async () => {
  stub({ scalarImpl: () => 42 });
  assert.deepEqual(await ex._enumList(ctx, 'q'), ['42']);
});

test('_enumList：单值无逗号 → 单元素数组', async () => {
  stub({ scalarImpl: () => 'onlydb' });
  assert.deepEqual(await ex._enumList(ctx, 'q'), ['onlydb']);
});

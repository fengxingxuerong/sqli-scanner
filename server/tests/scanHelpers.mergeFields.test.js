// ============================================================================
// tests/scanHelpers.mergeFields.test.js —— 提取结果合并的「字段完整性」测试
//
// 背景（2026-09-12 实测发现）：mergeExtracted 是**逐字段白名单**合并。
// 白名单漏掉某个字段，对应功能在报告里就恒为空——extractByScope 明明产出了数据，
// 合并层却把它丢掉。--search 就这样坏了很久（实测 --search user 在报告里 matchedTables 恒为空，
// 直连提取层却有结果）。新增枚举字段时必须同步补白名单，本文件就是那道闸。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeExtracted, mergeExtractedForResume, hasData } from '../src/engine/scanHelpers.js';
import { emptyExtractedData } from '../src/engine/models.js';

test('mergeExtracted：search 结果必须被保留（--search 曾在此丢失）', () => {
  const target = emptyExtractedData();
  mergeExtracted(target, {
    search: { keyword: 'user', matchedTables: ['shop.users'], matchedColumns: ['shop.users.name'] },
  });
  assert.ok(target.search, 'search 字段不能丢');
  assert.equal(target.search.keyword, 'user');
  assert.deepEqual(target.search.matchedTables, ['shop.users']);
  assert.deepEqual(target.search.matchedColumns, ['shop.users.name']);
});

test('mergeExtracted：多次合并 search 取并集并去重（多注入点各提一次）', () => {
  const target = emptyExtractedData();
  mergeExtracted(target, { search: { keyword: 'u', matchedTables: ['a.t1'] } });
  mergeExtracted(target, { search: { keyword: 'u', matchedTables: ['a.t1', 'a.t2'], matchedColumns: ['a.t1.c'] } });
  assert.deepEqual(target.search.matchedTables.sort(), ['a.t1', 'a.t2']);
  assert.deepEqual(target.search.matchedColumns, ['a.t1.c']);
});

test('mergeExtracted：meta 必须被保留（dumpUnconfirmed 曾在此丢失）', () => {
  const target = emptyExtractedData();
  mergeExtracted(target, { meta: { dumpUnconfirmed: ['db.t1'] } });
  assert.deepEqual(target.meta.dumpUnconfirmed, ['db.t1']);
});

test('hasData：只有 search 命中也算"有数据"', () => {
  const d = emptyExtractedData();
  assert.equal(hasData(d), false, '空结果不算有数据');
  d.search = { keyword: 'u', matchedTables: ['a.t'], matchedColumns: [] };
  assert.equal(hasData(d), true, '仅搜索命中也是有效提取结果');
});

test('mergeExtractedForResume：resume 恢复时 search 不丢', () => {
  const cur = emptyExtractedData();
  const restored = { ...emptyExtractedData(), search: { keyword: 'k', matchedTables: ['x.y'] } };
  const out = mergeExtractedForResume(cur, restored);
  assert.deepEqual(out.search.matchedTables, ['x.y']);
});

test('回归：既有字段合并语义未被破坏', () => {
  const target = emptyExtractedData();
  mergeExtracted(target, {
    databases: ['db1'],
    tables: { db1: ['t1'] },
    rows: { 'db1.t1': [{ a: 1 }] },
    currentUser: 'root@localhost',
  });
  assert.deepEqual(target.databases, ['db1']);
  assert.deepEqual(target.tables.db1, ['t1']);
  assert.equal(target.currentUser, 'root@localhost');
});

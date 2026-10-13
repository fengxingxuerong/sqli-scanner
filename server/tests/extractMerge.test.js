// ============================================================================
// tests/extractMerge.test.js —— 提取合并单核等价性测试（design §2.1.3.9）
//
// 验证：
// ① mergeFields overwrite 策略与 mergeExtracted 行为等价
// ② mergeFields keep 策略与 mergeExtractedForResume 行为等价
// ③ FIELD_TABLE 覆盖所有报告字段（字段集一致性——历史 P0-FIX 两次栽在漏字段）
// ④ 各字段类别（union/shallow/scalar/search）在两种策略下语义正确
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeFields, FIELD_TABLE } from '../src/engine/extractMerge.js';
import { mergeExtracted, mergeExtractedForResume } from '../src/engine/scanHelpers.js';
import { emptyExtractedData } from '../src/engine/models.js';

const ALL_FIELDS = FIELD_TABLE.map((f) => f.name);

function fullSrc() {
  return {
    databases: ['db2'],
    tables: { db2: ['t2'] },
    columns: { 'db2.t2': ['c2'] },
    rows: { 'db2.t2': [{ c2: 2 }] },
    counts: { 'db2.t2': 5 },
    schemas: { db2: ['s2'] },
    meta: { dumpUnconfirmed: ['db2.t2'] },
    currentDb: 'db2',
    currentUser: 'user2@host',
    users: ['user2'],
    passwords: [{ user: 'user2', hash: 'x' }],
    passwordAnalysis: { cracked: ['user2'] },
    hostname: 'host2',
    isDba: true,
    userPrivs: { user2: ['ALL'] },
    roles: { user2: ['admin'] },
    search: { keyword: 'admin', matchedTables: ['db2.users'], matchedColumns: ['db2.users.name'] },
  };
}

test('① overwrite 策略：mergeFields 与 mergeExtracted 行为等价', () => {
  const t1 = emptyExtractedData();
  const t2 = emptyExtractedData();
  const src = fullSrc();
  mergeExtracted(t1, src);
  mergeFields(t2, src, { onConflict: 'overwrite' });
  assert.deepEqual(t1, t2, '两函数合并结果应一致');
});

test('② keep 策略：mergeFields 与 mergeExtractedForResume 行为等价', () => {
  const cur = emptyExtractedData();
  cur.databases.push('existing_db');
  cur.currentUser = 'existing_user';
  const restored = fullSrc();
  const out1 = mergeExtractedForResume(cur, restored);
  const out2 = structuredClone(cur);
  mergeFields(out2, restored, { onConflict: 'keep' });
  assert.deepEqual(out1, out2, '两函数合并结果应一致');
});

test('③ FIELD_TABLE 覆盖所有报告字段', () => {
  const expected = [
    'databases', 'tables', 'columns', 'rows', 'counts', 'schemas', 'meta',
    'currentDb', 'currentUser', 'users', 'passwords', 'passwordAnalysis',
    'hostname', 'isDba', 'userPrivs', 'roles', 'search',
  ].sort();
  assert.deepEqual(ALL_FIELDS.slice().sort(), expected, '字段清单应覆盖所有报告字段');
});

test('④ union 字段（databases）：两种策略都是去重并集', () => {
  const t1 = emptyExtractedData();
  t1.databases.push('db1');
  mergeFields(t1, { databases: ['db1', 'db2'] }, { onConflict: 'overwrite' });
  assert.deepEqual(t1.databases.sort(), ['db1', 'db2'], 'overwrite: 去重并集');

  const t2 = emptyExtractedData();
  t2.databases.push('db1');
  mergeFields(t2, { databases: ['db1', 'db2'] }, { onConflict: 'keep' });
  assert.deepEqual(t2.databases.sort(), ['db1', 'db2'], 'keep: 去重并集');
});

test('④ shallow 字段（tables）：overwrite 时 src 覆盖，keep 时 target 优先', () => {
  const t1 = emptyExtractedData();
  t1.tables = { db1: ['t1'] };
  mergeFields(t1, { tables: { db1: ['t2'], db2: ['t3'] } }, { onConflict: 'overwrite' });
  assert.deepEqual(t1.tables, { db1: ['t2'], db2: ['t3'] }, 'overwrite: src 覆盖 target');

  const t2 = emptyExtractedData();
  t2.tables = { db1: ['t1'] };
  mergeFields(t2, { tables: { db1: ['t2'], db2: ['t3'] } }, { onConflict: 'keep' });
  assert.deepEqual(t2.tables, { db1: ['t1'], db2: ['t3'] }, 'keep: target 优先，src 补缺');
});

test('④ scalar 字段（currentDb）：overwrite 时 src 覆盖，keep 时 target 优先', () => {
  const t1 = emptyExtractedData();
  t1.currentDb = 'old';
  mergeFields(t1, { currentDb: 'new' }, { onConflict: 'overwrite' });
  assert.equal(t1.currentDb, 'new', 'overwrite: src 覆盖');

  const t2 = emptyExtractedData();
  t2.currentDb = 'old';
  mergeFields(t2, { currentDb: 'new' }, { onConflict: 'keep' });
  assert.equal(t2.currentDb, 'old', 'keep: target 优先');

  const t3 = emptyExtractedData();
  mergeFields(t3, { currentDb: 'new' }, { onConflict: 'keep' });
  assert.equal(t3.currentDb, 'new', 'keep: target 缺失时 src 填补');
});

test('④ search 字段：overwrite 时 keyword 覆盖 + matched 并集', () => {
  const t = emptyExtractedData();
  t.search = { keyword: 'old', matchedTables: ['a.t1'], matchedColumns: ['a.t1.c1'] };
  mergeFields(t, {
    search: { keyword: 'new', matchedTables: ['a.t1', 'a.t2'], matchedColumns: ['a.t2.c2'] },
  }, { onConflict: 'overwrite' });
  assert.equal(t.search.keyword, 'new', 'keyword: src 覆盖');
  assert.deepEqual(t.search.matchedTables.sort(), ['a.t1', 'a.t2'], 'matchedTables: 去重并集');
  assert.deepEqual(t.search.matchedColumns.sort(), ['a.t1.c1', 'a.t2.c2'], 'matchedColumns: 去重并集');
});

test('④ search 字段：keep 时 target 已有则整段保留', () => {
  const t = emptyExtractedData();
  t.search = { keyword: 'old', matchedTables: ['a.t1'], matchedColumns: [] };
  mergeFields(t, {
    search: { keyword: 'new', matchedTables: ['a.t2'], matchedColumns: ['a.t2.c2'] },
  }, { onConflict: 'keep' });
  assert.equal(t.search.keyword, 'old', 'keyword: target 保留');
  assert.deepEqual(t.search.matchedTables, ['a.t1'], 'matchedTables: target 保留');
});

test('④ search 字段：keep 时 target 缺失则从 src 克隆', () => {
  const t = emptyExtractedData();
  mergeFields(t, {
    search: { keyword: 'new', matchedTables: ['a.t2'], matchedColumns: ['a.t2.c2'] },
  }, { onConflict: 'keep' });
  assert.equal(t.search.keyword, 'new');
  assert.deepEqual(t.search.matchedTables, ['a.t2']);
});

test('P0-FIX 回归：passwords + passwordAnalysis 不丢', () => {
  const t = emptyExtractedData();
  mergeFields(t, {
    passwords: [{ user: 'root', hash: 'abc' }],
    passwordAnalysis: { cracked: ['root'] },
  }, { onConflict: 'overwrite' });
  assert.deepEqual(t.passwords, [{ user: 'root', hash: 'abc' }]);
  assert.deepEqual(t.passwordAnalysis, { cracked: ['root'] });
});

test('防御：src 为空对象时 target 不变', () => {
  const t = emptyExtractedData();
  t.databases.push('db1');
  mergeFields(t, {}, { onConflict: 'overwrite' });
  assert.deepEqual(t.databases, ['db1']);
});

test('防御：src 字段为 undefined 时不覆盖', () => {
  const t = emptyExtractedData();
  t.currentDb = 'existing';
  mergeFields(t, { currentDb: undefined }, { onConflict: 'overwrite' });
  assert.equal(t.currentDb, 'existing', 'undefined 不应覆盖已有值');
});
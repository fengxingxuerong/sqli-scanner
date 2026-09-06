// CLI --search 命令单测（对标 sqlmap --search）
// 覆盖：
//   1) parseArgs：--search <keyword> 解析
//   2) buildExtractScope：search 模式 scope 构造
//   3) isEnumMode：--search 触发枚举模式
//   4) ScanManager._extract：mock extractor 断言 search 模式返回正确结构
//   5) 限流：最多 3 库 × 10 表
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildExtractScope, buildConfig } from '../bin/cli.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// ─────────────── 1) parseArgs ───────────────
test('parseArgs: --search <keyword> 解析为字符串', () => {
  const a = parseArgs(['-u', 'http://x', '--search', 'user']);
  assert.equal(a.search, 'user');
});

test('parseArgs: 无 --search 时 search 为 null', () => {
  const a = parseArgs(['-u', 'http://x', '--dbs']);
  assert.equal(a.search, null);
});

// ─────────────── 2) buildExtractScope ───────────────
test('buildExtractScope: --search user → {mode:search, keyword:user}', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--search', 'user'])),
    { mode: 'search', keyword: 'user', excludeSysdbs: true });
});

test('buildExtractScope: --search 配合 --no-exclude-sysdbs', () => {
  const s = buildExtractScope(parseArgs(['-u', 'http://x', '--search', 'foo', '--no-exclude-sysdbs']));
  assert.equal(s.mode, 'search');
  assert.equal(s.keyword, 'foo');
  assert.equal(s.excludeSysdbs, false);
});

// ─────────────── 3) buildConfig ───────────────
test('buildConfig: --search → enableExtract=true', () => {
  assert.equal(buildConfig(parseArgs(['-u', 'http://x', '--search', 'foo'])).enableExtract, true);
});

// ─────────────── 4) ScanManager._extract search 模式 ───────────────
function mockExtractor(overrides = {}) {
  const calls = {};
  const ex = {
    calls,
    async enumerateDatabases(ctx) { calls.enumerateDatabases = (calls.enumerateDatabases || 0) + 1; return overrides.dbs ?? []; },
    async enumerateTables(ctx, db) { calls.enumerateTables = (calls.enumerateTables || 0) + 1; return overrides.tables?.[db] ?? []; },
    async enumerateColumns(ctx, db, t) { calls.enumerateColumns = (calls.enumerateColumns || 0) + 1; return overrides.columns?.[`${db}.${t}`] ?? []; },
  };
  return ex;
}

function makeSm(overrides) {
  const sm = new ScanManager();
  sm.extractor = mockExtractor(overrides);
  return sm;
}

function ctxWithScope(scope) {
  return { config: { extractScope: scope }, target: { config: { extractScope: scope } } };
}

test('_extract: mode=search 匹配表名和列名', async () => {
  const sm = makeSm({
    dbs: ['appdb', 'mydb'],
    tables: {
      appdb: ['users', 'orders', 'user_logs'],
      mydb: ['products', 'user_profiles'],
    },
    columns: {
      'appdb.users': ['id', 'username', 'email'],
      'appdb.orders': ['id', 'user_id', 'amount'],
      'appdb.user_logs': ['id', 'user_id', 'action'],
      'mydb.products': ['id', 'name', 'price'],
      'mydb.user_profiles': ['id', 'user_id', 'bio'],
    },
  });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'user', excludeSysdbs: true }));

  // 返回结构断言
  assert.ok(Array.isArray(data.databases), 'databases 应为数组');
  assert.ok(data.tables, 'tables 应存在');
  assert.ok(data.columns, 'columns 应存在');
  assert.ok(data.search, 'search 字段应存在');
  assert.equal(data.search.keyword, 'user');

  // 匹配的表名（包含 "user"）
  assert.ok(data.search.matchedTables.includes('appdb.users'));
  assert.ok(data.search.matchedTables.includes('appdb.user_logs'));
  assert.ok(data.search.matchedTables.includes('mydb.user_profiles'));
  // orders 不含 user
  assert.ok(!data.search.matchedTables.includes('appdb.orders'));

  // 匹配的列名（username 列含 user）
  const userCols = data.search.matchedColumns.find((m) => m.table === 'appdb.users');
  assert.ok(userCols, 'appdb.users 应有匹配列');
  assert.ok(userCols.columns.includes('username'));
  assert.ok(!userCols.columns.includes('id'));

  // user_id 列在多个表中匹配
  const ordersCols = data.search.matchedColumns.find((m) => m.table === 'appdb.orders');
  assert.ok(ordersCols, 'appdb.orders 应有匹配列 user_id');
  assert.ok(ordersCols.columns.includes('user_id'));
});

test('_extract: mode=search 无匹配时返回空数组', async () => {
  const sm = makeSm({
    dbs: ['appdb'],
    tables: { appdb: ['orders', 'products'] },
    columns: { 'appdb.orders': ['id', 'amount'], 'appdb.products': ['id', 'price'] },
  });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'xyz', excludeSysdbs: true }));

  assert.equal(data.search.matchedTables.length, 0);
  assert.equal(data.search.matchedColumns.length, 0);
});

test('_extract: mode=search 空 keyword 返回空结果', async () => {
  const sm = makeSm({ dbs: ['appdb'], tables: { appdb: ['t'] }, columns: { 'appdb.t': ['c'] } });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: '', excludeSysdbs: true }));
  assert.deepEqual(data.search.matchedTables, []);
  assert.deepEqual(data.search.matchedColumns, []);
});

// ─────────────── 5) 限流：最多 3 库 × 10 表 ───────────────
test('_extract: mode=search 最多搜索 3 个数据库', async () => {
  const sm = makeSm({
    dbs: ['db1', 'db2', 'db3', 'db4', 'db5'],
    tables: { db1: ['t1'], db2: ['t1'], db3: ['t1'], db4: ['t1'], db5: ['t1'] },
    columns: {},
  });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 't', excludeSysdbs: true }));

  // 只搜了前 3 个库
  assert.ok(data.tables['db1'], 'db1 应被搜索');
  assert.ok(data.tables['db2'], 'db2 应被搜索');
  assert.ok(data.tables['db3'], 'db3 应被搜索');
  assert.equal(data.tables['db4'], undefined, 'db4 不应被搜索');
  assert.equal(data.tables['db5'], undefined, 'db5 不应被搜索');
  // enumerateTables 只被调用 3 次（3 个库）
  assert.equal(sm.extractor.calls.enumerateTables, 3);
});

test('_extract: mode=search 每库最多搜索 10 个表', async () => {
  // 构造 15 个表，keyword 匹配所有（验证截断在 10）
  const manyTables = Array.from({ length: 15 }, (_, i) => `table_${i}`);
  const manyCols = {};
  for (const t of manyTables) manyCols[`db1.${t}`] = ['col'];
  const sm = makeSm({
    dbs: ['db1'],
    tables: { db1: manyTables },
    columns: manyCols,
  });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'table', excludeSysdbs: true }));

  // data.tables['db1'] 应被截断为 10 个
  assert.equal(data.tables['db1'].length, 10);
  // enumerateColumns 最多被调用 10 次（10 个表）
  assert.equal(sm.extractor.calls.enumerateColumns, 10);
  // 匹配的表名最多 10 个
  assert.equal(data.search.matchedTables.length, 10);
});

// ─────────────── 6) 强实现优先（消双实现漂移） ───────────────
test('_extract: mode=search 优先使用 searchTables/searchColumns 强实现（全库不截断）', async () => {
  // mock 提供 searchTables/searchColumns（真实 Extractor 有，旧 mock 没有）：
  // 应直接返回全库匹配，不再逐库枚举（enumerateTables/enumerateColumns 不被调用）
  const calls = { searchTables: 0, searchColumns: 0, enumerateTables: 0, enumerateColumns: 0 };
  const sm = new ScanManager();
  sm.extractor = {
    calls,
    async enumerateDatabases() { return ['db1', 'db2', 'db3', 'db4', 'db5']; }, // 5 库 > MAX_DBS=3
    async enumerateTables() { calls.enumerateTables++; return []; },
    async enumerateColumns() { calls.enumerateColumns++; return []; },
    async searchTables(ctx, term) {
      calls.searchTables++;
      return ['db1.users', 'db3.user_logs', 'db4.user_profiles', 'extra_db.credit_users'];
    },
    async searchColumns(ctx, term) {
      calls.searchColumns++;
      return ['db1.users.username', 'db1.users.user_type', 'db4.user_profiles.user_id', 'main.t2.user_flag'];
    },
  };
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'user', excludeSysdbs: true }));

  assert.equal(calls.searchTables, 1);
  assert.equal(calls.searchColumns, 1);
  // 强实现命中：不再回退到逐库枚举
  assert.equal(calls.enumerateTables, 0);
  assert.equal(calls.enumerateColumns, 0);

  // 匹配表跨全库（含 db4/extra_db，超出 MAX_DBS=3 截断范围）
  assert.ok(data.search.matchedTables.includes('db1.users'));
  assert.ok(data.search.matchedTables.includes('db4.user_profiles'));
  assert.ok(data.search.matchedTables.includes('extra_db.credit_users'));
  assert.equal(data.search.matchedTables.length, 4);

  // 匹配列按表聚合，含全库列（db4、main 前缀）
  const u1 = data.search.matchedColumns.find((m) => m.table === 'db1.users');
  assert.ok(u1, 'db1.users 应有匹配列');
  assert.ok(u1.columns.includes('username'));
  assert.ok(u1.columns.includes('user_type'));
  const u4 = data.search.matchedColumns.find((m) => m.table === 'db4.user_profiles');
  assert.ok(u4 && u4.columns.includes('user_id'), 'db4.user_profiles.user_id 应匹配（跨 3 库截断之外）');
  const mt = data.search.matchedColumns.find((m) => m.table === 'main.t2');
  assert.ok(mt && mt.columns.includes('user_flag'), 'main.t2.user_flag 应匹配（SQLite main. 前缀形态）');
});

test('_extract: mode=search 强实现返回空时降级朴素枚举（mock 无强方法路径回归）', async () => {
  // 强方法存在但返回 []（无匹配）→ 应降级朴素枚举兜底并得到同构结果
  const sm = new ScanManager();
  sm.extractor = {
    async enumerateDatabases() { return ['appdb']; },
    async enumerateTables(ctx, db) { return ['users', 'orders']; },
    async enumerateColumns(ctx, db, t) {
      if (t === 'users') return ['id', 'username'];
      return ['id', 'amount'];
    },
    async searchTables() { return []; },
    async searchColumns() { return []; },
  };
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'user', excludeSysdbs: true }));

  assert.ok(data.search.matchedTables.includes('appdb.users'));
  const mc = data.search.matchedColumns.find((m) => m.table === 'appdb.users');
  assert.ok(mc && mc.columns.includes('username'));
});

test('_extract: mode=search 强实现抛错时降级朴素枚举（不中断）', async () => {
  const sm = new ScanManager();
  sm.extractor = {
    async enumerateDatabases() { return ['appdb']; },
    async enumerateTables(ctx, db) { return ['users']; },
    async enumerateColumns(ctx, db, t) { return ['username', 'passwd']; },
    async searchTables() { throw new Error('强实现查询模板缺失'); },
    async searchColumns() { throw new Error('强实现查询模板缺失'); },
  };
  const data = await sm._extract('sid', ctxWithScope({ mode: 'search', keyword: 'user', excludeSysdbs: true }));

  assert.ok(data.search.matchedTables.includes('appdb.users'));
  const mc = data.search.matchedColumns.find((m) => m.table === 'appdb.users');
  assert.ok(mc && mc.columns.includes('username'));
});

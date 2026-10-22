// e2e/lib/sqliSchema 单测：schema 状态判定 + 幂等初始化
// 为什么值得测（D126，2026-10-22）：空库时 MySQL 靶站每条查询都 SQL 报错，
// 真/假响应同形 ⇒ boolean/time 全 miss，套件把「环境缺失」报成「真值漏检」
// （实测空库 1/11、有表 11/11）。判定与自愈逻辑判错，排障就会被引向引擎。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schemaVerdict, assertSafeDbName, probeSqliSchema, ensureSqliSchema } from './sqliSchema.mjs';

// ── 状态判定（纯函数）──
test('schemaVerdict：两表都有数据 → ok', () => {
  const v = schemaVerdict({ users: 6, products: 4 });
  assert.equal(v.ok, true);
  assert.deepEqual(v.missing, []);
  assert.deepEqual(v.empty, []);
  assert.equal(v.reason, '');
});

test('schemaVerdict：缺表（null）→ missing 精确点名', () => {
  const v = schemaVerdict({ users: null, products: 4 });
  assert.equal(v.ok, false);
  assert.deepEqual(v.missing, ['users']);
  assert.match(v.reason, /缺表：users/);
});

test('schemaVerdict：空表（0 行）与缺表是两回事', () => {
  const v = schemaVerdict({ users: 0, products: 0 });
  assert.equal(v.ok, false);
  assert.deepEqual(v.empty, ['users', 'products']);
  assert.deepEqual(v.missing, []);
  assert.match(v.reason, /空表/);
});

test('schemaVerdict：缺表优先于空表报出（先有表才谈行数）', () => {
  const v = schemaVerdict({ users: null, products: 0 });
  assert.deepEqual(v.missing, ['users']);
  assert.deepEqual(v.empty, ['products']);
  assert.match(v.reason, /缺表：users/);
});

// ── 库名校验（拼进 USE 前必须挡住）──
test('assertSafeDbName：合法标识符通过', () => {
  assert.equal(assertSafeDbName('sqli_lab'), 'sqli_lab');
  assert.equal(assertSafeDbName('lab$1'), 'lab$1');
});

test('assertSafeDbName：拼接注入直接抛错（不放行）', () => {
  for (const bad of ['sqli_lab`; DROP TABLE users; --', 'a b', 'x-y', '', null, undefined]) {
    assert.throws(() => assertSafeDbName(bad), /非法库名/);
  }
});

// ── 幂等初始化（fake connection 记录语句）──
// 关键：fake 必须模拟「CREATE TABLE 之后表就存在」—— 否则测不出 created 语义。
function fakeConn(state = {}) {
  const calls = [];
  const missing = new Set(state.missingTables || []);
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params });
      const s = String(sql);
      const useMatch = /^USE `([\w$]+)`/.exec(s);
      if (useMatch && state.noDb) {
        throw Object.assign(new Error('Unknown database'), { code: 'ER_BAD_DB_ERROR' });
      }
      const ddl = /CREATE TABLE IF NOT EXISTS `(\w+)`/.exec(s);
      if (ddl) {
        missing.delete(ddl[1]); // 建表后该表不再缺失
        return [{}];
      }
      const cnt = /^SELECT COUNT\(\*\) n FROM `(\w+)`/.exec(s);
      if (cnt) {
        const table = cnt[1];
        if (missing.has(table)) {
          throw Object.assign(new Error(`Table '${table}' doesn't exist`), { code: 'ER_NO_SUCH_TABLE' });
        }
        return [[{ n: state[table] ?? 0 }]];
      }
      return [{}];
    },
  };
}

test('probeSqliSchema：缺库 → ok=false 且给出原因（不抛错）', async () => {
  const conn = fakeConn({ noDb: true });
  const r = await probeSqliSchema(conn, { database: 'sqli_lab' });
  assert.equal(r.ok, false);
  assert.equal(r.schemaOk, false);
  assert.match(r.reason, /库不可用/);
  assert.deepEqual(r.missing, ['users', 'products']);
});

test('probeSqliSchema：库在但缺表 → ok=true、schemaOk=false、missing 点名', async () => {
  const conn = fakeConn({ missingTables: ['users'], products: 4 });
  const r = await probeSqliSchema(conn, { database: 'sqli_lab' });
  assert.equal(r.ok, true, '库可访问');
  assert.equal(r.schemaOk, false, '表不齐 → schema 未就绪');
  assert.deepEqual(r.missing, ['users']);
  assert.equal(r.counts.users, null);
  assert.equal(r.counts.products, 4);
});

test('ensureSqliSchema：整库为空 → 建表 + 灌两份种子，created 记全', async () => {
  const state = { missingTables: ['users', 'products'] };
  const conn = fakeConn(state);
  const r = await ensureSqliSchema(conn, { database: 'sqli_lab', quiet: true });
  assert.deepEqual(r.created.sort(), ['products', 'users']);
  assert.deepEqual(r.seeded.sort(), ['products', 'users']);
  const sqls = conn.calls.map((c) => c.sql);
  assert.ok(sqls.some((x) => /CREATE DATABASE IF NOT EXISTS/.test(x)), '应建库');
  assert.equal(sqls.filter((x) => /^INSERT INTO/.test(x)).length, 2, '两表各插一次种子');
});

test('ensureSqliSchema：已有数据 → 零 INSERT、created 为空（幂等，不覆盖）', async () => {
  const conn = fakeConn({ users: 6, products: 4 });
  const r = await ensureSqliSchema(conn, { database: 'sqli_lab', quiet: true });
  assert.deepEqual(r.created, []);
  assert.deepEqual(r.seeded, []);
  assert.equal(r.existing.users, 6);
  assert.equal(r.existing.products, 4);
  const inserts = conn.calls.filter((c) => /^INSERT INTO/.test(c.sql));
  assert.equal(inserts.length, 0, '有数据时不得插入');
});

test('ensureSqliSchema：表存在但空 → 只补种子，不重复建库错误', async () => {
  const conn = fakeConn({ users: 0, products: 0 });
  const r = await ensureSqliSchema(conn, { database: 'sqli_lab', quiet: true });
  assert.deepEqual(r.created, [], '表原本就在，不算新建');
  assert.deepEqual(r.seeded.sort(), ['products', 'users']);
});

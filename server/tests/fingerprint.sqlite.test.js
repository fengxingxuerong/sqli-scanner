// SQLite 指纹识别单测：unrecognized token 报错形态定库（Python sqli-labs L04/L14 漏检修复）
// + 负向约束（不误吞 MySQL/PG 报错文本）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dbmsFromError } from '../src/engine/payloads.js';

test('dbmsFromError: SQLite unrecognized token 形态定库为 SQLite', () => {
  // 真实形态（Python sqli-labs L04 报错原文）
  assert.equal(dbmsFromError('unrecognized token: ""1"")"'), 'SQLite');
  assert.equal(dbmsFromError('unrecognized token: ""))"'), 'SQLite');
  // sqlite3 驱动异常前缀形态
  assert.equal(dbmsFromError('sqlite3.OperationalError: near "x": syntax error'), 'SQLite');
});

test('dbmsFromError: 其他 SQLite 报错形态保持识别（回归）', () => {
  assert.equal(dbmsFromError('SQLite3::query failed'), 'SQLite');
  assert.equal(dbmsFromError('SQLITE_ERROR: no such table: users'), 'SQLite');
});

test('dbmsFromError: HTML 标签先剥除——正常页 <h2> 不误判为 H2 数据库', () => {
  // Python sqli-labs L04 实测根因：无报错正常页含 <h2>Level 4</h2>，
  // H2 签名（大小写不敏感 H2）命中标签文本 → 误定库 H2 → payload 族错配 → 漏检。
  assert.equal(dbmsFromError('<html><body><h2>Level 4</h2><p>No results found.</p></body></html>'), null);
  // 真实 H2 报错（含 org.h2 特征）仍正确识别
  assert.equal(dbmsFromError('<html><body><pre>org.h2.jdbc.JdbcSQLException: Syntax error</pre></body></html>'), 'H2');
});

test('dbmsFromError: MySQL 报错不被 SQLite 签名误吞（负向）', () => {
  const mysqlErr = "You have an error in your SQL syntax; check the manual ... near ''1''' at line 1";
  assert.equal(dbmsFromError(mysqlErr), 'MySQL');
  // PG 报错保持 PG
  assert.equal(dbmsFromError('ERROR: syntax error at or near "extractvalue"'), 'PostgreSQL');
});

// tamper 兼容性元数据（compat{dbms,conflicts}）单测
// 对标 sqlmap 各 tamper 的 dbms/dependencies 约束：避免 MySQL-only tamper 误用到 SQLite/PG 静默失效。
// 导入即触发内置插件注册（applyTampers.js 内部 registerMany），与 tamper.test.js 一致。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../src/core/tamper/applyTampers.js';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import { applyTampers } from '../src/core/tamper/applyTampers.js';

test('resolve 无 ctx（或不传 dbms）→ 不过滤，向后兼容', () => {
  assert.equal(tamperRegistry.resolve(['sleep2pg']).length, 1);
  assert.equal(tamperRegistry.resolve(['sleep2pg'], {}).length, 1);
  assert.equal(tamperRegistry.resolve(['sleep2pg'], { dbms: null }).length, 1);
});

test('resolve 按 ctx.dbms 过滤不兼容插件：sleep2pg 仅 PostgreSQL，SQLite 下被跳过', () => {
  const r = tamperRegistry.resolve(['sleep2pg'], { dbms: 'SQLite' });
  assert.equal(r.length, 0, 'SQLite 下 sleep2pg 应被跳过');
});

test('resolve 按 ctx.dbms 放行兼容插件：sleep2pg 在 PostgreSQL 下保留', () => {
  const r = tamperRegistry.resolve(['sleep2pg'], { dbms: 'PostgreSQL' });
  assert.equal(r.length, 1);
  assert.equal(r[0].name, 'sleep2pg');
});

test('resolve 多 DBMS 作用域：space2mysqlblank 仅 MySQL/MariaDB', () => {
  assert.equal(tamperRegistry.resolve(['space2mysqlblank'], { dbms: 'SQLite' }).length, 0);
  assert.equal(tamperRegistry.resolve(['space2mysqlblank'], { dbms: 'SQL Server' }).length, 0);
  assert.equal(tamperRegistry.resolve(['space2mysqlblank'], { dbms: 'MySQL' }).length, 1);
  assert.equal(tamperRegistry.resolve(['space2mysqlblank'], { dbms: 'MariaDB' }).length, 1);
});

test('resolve 无 dbms 限制的插件永不被过滤：space2comment 在任意 dbms 下保留', () => {
  assert.equal(tamperRegistry.resolve(['space2comment'], { dbms: 'SQLite' }).length, 1);
  assert.equal(tamperRegistry.resolve(['space2comment'], { dbms: 'PostgreSQL' }).length, 1);
});

test('resolve 冲突检测不丢弃插件：space2comment 与 space2plus 冲突仍都入选（仅告警）', () => {
  const r = tamperRegistry.resolve(['space2comment', 'space2plus']);
  assert.equal(r.length, 2, '冲突应告警但不移除');
  assert.deepEqual(r.map((p) => p.name), ['space2comment', 'space2plus']);
});

test('resolve 严格保持 names 数组顺序（链式顺序由数组决定）', () => {
  const r = tamperRegistry.resolve(['lowercase', 'space2comment', 'uppercase']);
  assert.deepEqual(r.map((p) => p.name), ['lowercase', 'space2comment', 'uppercase']);
});

test('applyTampers 顺序串联：space2comment→lowercase 顺序生效', () => {
  const out = applyTampers('SELECT 1', { dbms: 'SQLite' }, ['space2comment', 'lowercase']);
  assert.equal(out, 'select/**/1');
});

test('applyTampers 兼容过滤在链式中也生效：SQLite 下 space2mysqlblank 被跳过', () => {
  // space2mysqlblank 在 SQLite 被过滤 → 仅 space2comment 生效
  const out = applyTampers('SELECT 1', { dbms: 'SQLite' }, ['space2comment', 'space2mysqlblank']);
  assert.equal(out, 'SELECT/**/1');
});

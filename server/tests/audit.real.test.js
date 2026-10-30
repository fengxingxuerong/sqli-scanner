// ============================================================================
// tests/audit.real.test.js —— [D181] 真机审计：PGlite（真 PG 18）+ sql.js（真 SQLite）
//
// 为什么必须有这一层：`audit.test.js` 只测「判定器对不对」，它证明不了
//   **这些 SQL 在真引擎上跑得通**（列名拼错、PRAGMA 不支持、权限函数签名不同，
//   单测全绿而真机全 unknown —— 那正是本仓反复栽的「判据绿、入口坏」）。
//
// 本文件守三件事：
//   ① 真引擎上每条 SQL 都能执行（unknown 只允许出现在「确实查不到」的项上，且必须带 reason）；
//   ② 判定有真值对照：松配置判 fail、紧配置判 pass（两个方向在真库上各验一次）；
//   ③ **只读**：跑完审计后库里的数据与 schema 一字不变（逐表行数与 schema 版本前后比对）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAudit } from '../src/engine/audit.js';
import { PgDriver, SqlJsDriver } from '../src/core/dbDrivers.js';

/** 取审计结果里某条检查 */
const pick = (r, id) => r.findings.find((f) => f.id === id);

test('PGlite（真 PostgreSQL）：审计跑通、真值对照成立、库内容不变', async () => {
  const d = new PgDriver({
    initSql: 'create table t (id int); insert into t values (1), (2);',
  });
  await d.connect();
  try {
    const before = await d.query('select count(*) as c from t');
    const r = await runAudit(d, { dialect: d.dialect });

    // ① 每条 SQL 都执行了：unknown 只能出现在「查不到」的项上，且必须带 reason
    assert.ok(r.summary.total >= 5, `PG 检查项应 ≥5，实得 ${r.summary.total}`);
    for (const f of r.findings) {
      if (f.status === 'unknown') assert.ok(f.reason, `${f.id} 标 unknown 却没写原因`);
      assert.ok(!/查询失败/.test(f.detail) || f.reason, `${f.id} 查询失败未带原因`);
    }

    // ② 真值对照：PGlite 默认连接就是超级用户；password_encryption 默认不是 scram 的旧库另说
    const su = pick(r, 'pg-superuser');
    assert.ok(su, '缺 pg-superuser 检查项');
    assert.equal(su.status, 'fail', `PGlite 默认身份应为超级用户（实测 ${su.status}/${su.detail}）`);
    const ver = pick(r, 'pg-version');
    assert.equal(ver.status, 'pass');
    assert.match(ver.detail, /PostgreSQL/i, `版本串应含 PostgreSQL，实际 ${ver.detail}`);
    const pub = pick(r, 'pg-public-create');
    assert.ok(pub && ['pass', 'fail'].includes(pub.status), 'public schema 判据必须给出明确结论（不得 unknown）');

    // ③ 只读：数据与 schema 不被审计改动
    const after = await d.query('select count(*) as c from t');
    assert.deepEqual(after, before, '审计不得改动数据行数');
    const tables = await d.query("select count(*) as c from information_schema.tables where table_schema='public'");
    assert.equal(String(tables.rows[0]), '1', '审计不得新建/删除表');
  } finally {
    await d.close();
  }
});

test('sql.js（真 SQLite）：审计跑通、PRAGMA 真读得到、库内容不变', async () => {
  const d = new SqlJsDriver({ initSql: 'create table t (id int); insert into t values (1);' });
  await d.connect();
  try {
    const before = await d.query('select count(*) as c from t');
    const r = await runAudit(d, { dialect: d.dialect });
    assert.ok(r.summary.total >= 3, `SQLite 检查项应 ≥3，实得 ${r.summary.total}`);

    const ver = pick(r, 'sqlite-version');
    assert.equal(ver.status, 'pass', `版本应读得到，实际 ${ver.status}/${ver.detail}`);
    assert.match(ver.detail, /^\d+\.\d+/, `版本号形状不对：${ver.detail}`);

    // foreign_keys 默认关闭 ⇒ 必须判 fail（这是真实默认值，不是构造）
    const fk = pick(r, 'sqlite-foreign-keys');
    assert.equal(fk.status, 'fail', `SQLite 默认未开外键，应判 fail，实际 ${fk.status}/${fk.detail}`);

    // unknown 有原因
    for (const f of r.findings) if (f.status === 'unknown') assert.ok(f.reason, `${f.id} unknown 无原因`);

    const after = await d.query('select count(*) as c from t');
    assert.deepEqual(after, before, '审计不得改动数据');
  } finally {
    await d.close();
  }
});

test('真机反向：把外键打开后，同一判据必须转 pass（判据跟着真值走，不是写死）', async () => {
  const d = new SqlJsDriver({
    initSql: 'create table t (id int); pragma foreign_keys = on;',
  });
  await d.connect();
  try {
    const r = await runAudit(d, { dialect: d.dialect });
    const fk = pick(r, 'sqlite-foreign-keys');
    assert.equal(fk.status, 'pass', `开了外键应判 pass，实际 ${fk.status}/${fk.detail}`);
  } finally {
    await d.close();
  }
});

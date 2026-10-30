// [D186] MSSQL 审计检查项判据测试 —— judges 用真实 SQL Server 2022 引擎（LocalDB 16.0.1000.6）
// 的实跑输出作夹具（2026-10-27 取证，见 docs/审计口径.md「SQL Server」节与 CHANGELOG D185/D186）。
// 判据语义钉死：
//   1) version / current_user：真实引擎返回非空 ⇒ pass，且 detail 携带引擎原文；
//   2) sysadmin='yes' ⇒ fail(high)（真实高危形态：LocalDB 属主连接即 sysadmin）；
//      sysadmin='no' ⇒ pass（普通账号的诚实口径）。
//   3) 只读语义由 audit.test.js ⑤ 遍历 CHECKS_BY_DIALECT 自动覆盖（本文件不重复）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHECKS_BY_DIALECT } from '../src/engine/auditChecks.js';

const byId = (id) => CHECKS_BY_DIALECT.mssql.find((c) => c.id === id);

test('auditChecks.mssql: 方言表含 mssql 三项，id/严重度齐全', () => {
  const ids = CHECKS_BY_DIALECT.mssql.map((c) => c.id);
  assert.deepEqual(ids, ['mssql-version', 'mssql-current-user', 'mssql-sysadmin']);
  assert.equal(byId('mssql-sysadmin').severity, 'high');
});

test('auditChecks.mssql: version judge 对真实引擎输出判 pass（detail 带版本原文）', () => {
  // 2026-10-27 LocalDB 实跑：select @@version 的首行
  const realRow = ['Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) '];
  const r = byId('mssql-version').judge(realRow);
  assert.equal(r.status, 'pass');
  assert.match(r.detail, /16\.0\.1000\.6/);
});

test('auditChecks.mssql: current_user judge 对真实引擎输出判 pass', () => {
  const realRow = ['ADMIN\\Admin（无密码）'];
  const r = byId('mssql-current-user').judge(realRow);
  assert.equal(r.status, 'pass');
  assert.equal(r.detail, 'ADMIN\\Admin（无密码）');
});

test('auditChecks.mssql: sysadmin=yes 判 fail（真实高危形态），=no 判 pass', () => {
  const fail = byId('mssql-sysadmin').judge(['yes']);
  assert.equal(fail.status, 'fail');
  assert.match(fail.detail, /sysadmin/);
  const pass = byId('mssql-sysadmin').judge(['no']);
  assert.equal(pass.status, 'pass');
});

test('auditChecks.mssql: 查询空结果（firstValue 空）时 info 项判 fail 而非静默通过', () => {
  assert.equal(byId('mssql-version').judge(['']).status, 'fail');
  assert.equal(byId('mssql-current-user').judge([]).status, 'fail');
});

test('dbDrivers.dsn: mssql:// 方言解析进 dsnFields（host/user/password/database）', async () => {
  const { dsnFields } = await import('../src/core/dbDrivers.js');
  assert.deepEqual(dsnFields('mssql://sa:SqLi_2026_T!@127.0.0.1:65039/sqli_lab_mssql'), {
    user: 'sa',
    password: 'SqLi_2026_T!',
    host: '127.0.0.1',
    port: 65039,
    database: 'sqli_lab_mssql',
  });
  // LocalDB 形态：host 为 '(localdb)\\实例名'（%5C 解码），无凭据键（走集成认证）
  const f = dsnFields('mssql://(localdb)%5Csqli-audit/sqli_lab_mssql');
  assert.equal(f.host, '(localdb)\\sqli-audit');
  assert.equal('user' in f, false);
  assert.equal(f.database, 'sqli_lab_mssql');
});

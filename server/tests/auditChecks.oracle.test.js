// [D187] Oracle 审计检查项判据测试 —— judges 用真实 Oracle AI Database 26ai Free
// （23.26.3.0.0，FREEPDB1，SYS SYSDBA）的实跑输出作夹具（2026-10-28 取证，
// 见 docs/审计口径.md「Oracle」节与 CHANGELOG D187）。
// 判据语义钉死：
//   1) version / current_user：真实引擎返回非空 ⇒ pass，detail 携带引擎原文；
//   2) ISDBA=TRUE ⇒ fail(high)（SYS SYSDBA 连接的真实形态）；FALSE ⇒ pass；
//   3) DBA 角色 / CREATE ANY DIRECTORY 按「有无行」判 fail/pass（空结果不是错误）；
//   4) 默认 profile 的 PASSWORD_VERIFY_FUNCTION 为 'NULL' ⇒ fail(medium)，
//      真实校验函数名 ⇒ pass；空结果判 fail 并写原因（不静默通过）。
// 只读语义由 audit.test.js ⑤ 遍历 CHECKS_BY_DIALECT 自动覆盖（本文件不重复）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHECKS_BY_DIALECT } from '../src/engine/auditChecks.js';

const byId = (id) => CHECKS_BY_DIALECT.oracle.find((c) => c.id === id);

test('auditChecks.oracle: 方言表含 oracle 六项，id/严重度齐全', () => {
  const ids = CHECKS_BY_DIALECT.oracle.map((c) => c.id);
  assert.deepEqual(ids, [
    'oracle-version',
    'oracle-current-user',
    'oracle-sysdba',
    'oracle-dba-role',
    'oracle-password-verify',
    'oracle-directory-priv',
  ]);
  assert.equal(byId('oracle-sysdba').severity, 'high');
  assert.equal(byId('oracle-directory-priv').severity, 'high');
  assert.equal(byId('oracle-dba-role').severity, 'medium');
  assert.equal(byId('oracle-password-verify').severity, 'medium');
});

test('auditChecks.oracle: version judge 对真实引擎输出判 pass（detail 带版本原文）', () => {
  // 2026-10-28 真机实跑：select banner from v$version where rownum = 1
  const realRow = { v: 'Oracle AI Database 26ai Free Release 23.26.3.0.0 - Develop, Learn, and Run for Free' };
  const r = byId('oracle-version').judge(realRow);
  assert.equal(r.status, 'pass');
  assert.match(r.detail, /26ai/);
});

test('auditChecks.oracle: current_user judge 对真实输出判 pass（SYS / 普通账号两形态）', () => {
  assert.equal(byId('oracle-current-user').judge({ u: 'SYS' }).detail, 'SYS');
  assert.equal(byId('oracle-current-user').judge({ u: 'AUDIT_PROBE' }).status, 'pass');
  assert.equal(byId('oracle-current-user').judge(undefined).status, 'fail');
});

test('auditChecks.oracle: ISDBA=TRUE 判 fail（真实高危形态），FALSE 判 pass', () => {
  const fail = byId('oracle-sysdba').judge({ isdba: 'TRUE' });
  assert.equal(fail.status, 'fail');
  assert.match(fail.detail, /注入/);
  assert.equal(byId('oracle-sysdba').judge({ isdba: 'FALSE' }).status, 'pass');
});

test('auditChecks.oracle: DBA 角色「有行=有角色」判 fail，空结果判 pass', () => {
  assert.equal(byId('oracle-dba-role').judge({ d: 'yes' }).status, 'fail');
  assert.equal(byId('oracle-dba-role').judge(undefined).status, 'pass');
});

test('auditChecks.oracle: 默认 profile 未启用口令校验函数（LIMIT=NULL）判 fail，真实函数名判 pass', () => {
  // 真机实跑：低权账号 dba_profiles 不可见 ⇒ 该条走 unknown（由 audit.js 兜底，不在本文件）
  assert.equal(byId('oracle-password-verify').judge({ v: 'NULL' }).status, 'fail');
  assert.equal(byId('oracle-password-verify').judge({ v: 'ORA12C_STRONG_VERIFY_FUNCTION' }).status, 'pass');
  assert.equal(byId('oracle-password-verify').judge(undefined).status, 'fail');
});

test('auditChecks.oracle: CREATE ANY DIRECTORY「有行」判 fail（UTL_FILE 文件读写路径）', () => {
  const fail = byId('oracle-directory-priv').judge({ p: 'CREATE ANY DIRECTORY' });
  assert.equal(fail.status, 'fail');
  assert.match(fail.detail, /UTL_FILE/);
  assert.equal(byId('oracle-directory-priv').judge(undefined).status, 'pass');
});

test('dbDrivers.dsn: oracle:// 解析含 ?privilege=SYSDBA（SYS 连接必需）', async () => {
  const { dsnFields, driverTypeFromConnectionString } = await import('../src/core/dbDrivers.js');
  assert.deepEqual(
    dsnFields('oracle://SYS:SqLi_2026_0!@127.0.0.1:1521/FREEPDB1?privilege=SYSDBA'),
    {
      user: 'SYS',
      password: 'SqLi_2026_0!',
      host: '127.0.0.1',
      port: 1521,
      database: 'FREEPDB1',
      privilege: 'SYSDBA',
    }
  );
  // 无特权参数时不产生 privilege 键（其它方言零影响）
  assert.equal('privilege' in dsnFields('mysql://u:p@h/db'), false);
  assert.equal(driverTypeFromConnectionString('oracle://u:p@h:1521/svc'), 'oracle');
});

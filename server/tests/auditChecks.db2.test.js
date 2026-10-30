// [D189] DB2 审计检查项判据测试 —— judges 用真实 IBM Db2 v11.5.8.0 容器
// （ibmcom/db2:latest @ VMware Ubuntu 24.04 VM，db2inst1 属主 / db2fenc1 低权双形态）
// 的实跑输出作夹具（2026-10-29 取证，见 docs/审计口径.md「IBM Db2」节与 CHANGELOG D189）。
// 判据语义钉死：
//   1) version / current_user：真实引擎返回非空 ⇒ pass，detail 携带引擎原文；
//   2) 实例级权限用 SYSPROC.AUTH_LIST_AUTHORITIES_FOR_AUTHID 表函数（syscat.dbauth 是库级授权表，
//      不含 SYSADM/SYSCTRL）；属主经组授予的 SYSADM 形态为 d_user='*'、d_group='Y'，
//      仅 d_user/d_group 之一为 'Y' 才算持有（'*'+'N' 不是持有）；
//   3) DBADM 授予面：count>2 判 fail(medium)，≤2 判 pass；读不到计数判 fail（不静默通过）。
// 只读语义由 audit.test.js ⑤ 遍历 CHECKS_BY_DIALECT 自动覆盖（本文件不重复）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHECKS_BY_DIALECT } from '../src/engine/auditChecks.js';

const byId = (id) => CHECKS_BY_DIALECT.db2.find((c) => c.id === id);

test('auditChecks.db2: 方言表含 db2 四项，id/严重度齐全', () => {
  const ids = CHECKS_BY_DIALECT.db2.map((c) => c.id);
  assert.deepEqual(ids, [
    'db2-version',
    'db2-current-user',
    'db2-instance-authority',
    'db2-dbadm-holders',
  ]);
  assert.equal(byId('db2-instance-authority').severity, 'high');
  assert.equal(byId('db2-dbadm-holders').severity, 'medium');
});

test('auditChecks.db2: version judge 对真实引擎输出判 pass（detail 带版本原文）', () => {
  // 2026-10-29 真机实跑：select service_level as v from sysibmadm.env_inst_info
  const realRow = { v: 'DB2 v11.5.8.0' };
  const r = byId('db2-version').judge(realRow);
  assert.equal(r.status, 'pass');
  assert.match(r.detail, /11\.5\.8\.0/);
  assert.equal(byId('db2-version').judge(undefined).status, 'fail');
});

test('auditChecks.db2: current_user judge 对真实输出判 pass（属主 / 低权两形态）', () => {
  // 真机实跑：属主返回 DB2INST1、低权 db2fenc1 返回 DB2FENC1（OS 认证一律大写）
  assert.equal(byId('db2-current-user').judge({ u: 'DB2INST1' }).detail, 'DB2INST1');
  assert.equal(byId('db2-current-user').judge({ u: 'DB2FENC1' }).status, 'pass');
  assert.equal(byId('db2-current-user').judge(undefined).status, 'fail');
});

test('auditChecks.db2: SYSADM 经组授予（d_user=* d_group=Y）判 fail——属主真实高危形态', () => {
  // 真机实跑（db2inst1）：auth_list_authorities_for_authid 返回行 ['SYSADM']
  const fail = byId('db2-instance-authority').judge({ y: 'SYSADM' });
  assert.equal(fail.status, 'fail');
  assert.match(fail.detail, /读写任意表/);
  // 低权 db2fenc1 真机实跑：同查询空结果 ⇒ pass
  assert.equal(byId('db2-instance-authority').judge(undefined).status, 'pass');
});

test('auditChecks.db2: DBADM 授予面 count≤2 判 pass（真机=1），>2 判 fail，读不到判 fail', () => {
  // 真机实跑：select count(*) ... dbadmauth='Y' and grantee<>'SYSADM' → 1
  assert.equal(byId('db2-dbadm-holders').judge({ n: '1' }).status, 'pass');
  assert.equal(byId('db2-dbadm-holders').judge({ n: 1 }).status, 'pass');
  assert.equal(byId('db2-dbadm-holders').judge({ n: '5' }).status, 'fail');
  assert.match(byId('db2-dbadm-holders').judge({ n: '5' }).detail, /5 个身份/);
  assert.equal(byId('db2-dbadm-holders').judge(undefined).status, 'fail');
  assert.equal(byId('db2-dbadm-holders').judge({ n: 'abc' }).status, 'fail');
});

test('dbDrivers.dsn: db2:// 解析 + scheme 推断（ibm_db 未装时 DIRECT_DRIVER_UNAVAILABLE，不静默回退）', async () => {
  const { dsnFields, driverTypeFromConnectionString } = await import('../src/core/dbDrivers.js');
  assert.deepEqual(
    dsnFields('db2://db2inst1:P%40ss@127.0.0.1:50000/testdb'),
    { user: 'db2inst1', password: 'P@ss', host: '127.0.0.1', port: 50000, database: 'testdb' }
  );
  assert.equal(driverTypeFromConnectionString('db2://u:p@h:50000/db'), 'db2');
  assert.equal(driverTypeFromConnectionString('oracle://u:p@h:1521/svc'), 'oracle');
  // 未知 scheme 仍回退 memory（零回归）
  assert.equal(driverTypeFromConnectionString('foo://x'), 'memory');
  // 无 DB2_PASSWORD 环境变量且 DSN 无口令时，驱动 connect 走 ibm_db 缺失/连接失败路径——
  // 这里只钉「未安装不静默回退 memory」：getDriver 对显式 db2 类型必须抛错而非退桩
  const { getDriver } = await import('../src/core/dbDrivers.js');
  await assert.rejects(
    () => getDriver({ db: { driverType: 'db2', host: '127.0.0.1', port: 1, user: 'x', password: 'y', database: 'testdb' } }),
    (e) => {
      // ibm_db 已装（本机取证环境）⇒ 走到连接层报通信错；未装 ⇒ AppError 6011；
      // 两者都不是「静默回退 memory 自检桩」
      const msg = String(e && e.message || e);
      return /ibm_db|SQL30081|SQL30061|SQL1031|连接/i.test(msg) || e.code === 'ERR_DIRECT_DRIVER_UNAVAILABLE';
    }
  );
});

// dbDrivers 直连驱动选择测试（对标 sqlmap -d 语义）
// 覆盖：
//   1) driverTypeFromConnectionString：按 scheme 推断 mysql/postgres/mssql/oracle/sqlite
//   2) getDriver：显式 driverType 内置驱动（sqljs/memory）
//   3) getDriver：connectionString 推断 + 缺省回退 memory
//   4) getDriver：未注册真实驱动明确报错（不再静默回退 memory）
//   5) registerDriver：注册后真实驱动工厂被调用
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { driverTypeFromConnectionString, getDriver, registerDriver, registeredDrivers } from '../src/core/dbDrivers.js';
import { MemoryRecordDriver } from '../src/core/dbDrivers.js';

test('driverTypeFromConnectionString: 常见 connectionString scheme 推断', () => {
  assert.equal(driverTypeFromConnectionString('mysql://user:pass@127.0.0.1:3306/db'), 'mysql');
  assert.equal(driverTypeFromConnectionString('postgres://user:pass@host/db'), 'postgres');
  assert.equal(driverTypeFromConnectionString('postgresql://user:pass@host/db'), 'postgres');
  assert.equal(driverTypeFromConnectionString('mssql://sa:pass@host/db'), 'mssql');
  assert.equal(driverTypeFromConnectionString('sqlserver://sa:pass@host/db'), 'mssql');
  assert.equal(driverTypeFromConnectionString('oracle://user:pass@host:1521/sid'), 'oracle');
  assert.equal(driverTypeFromConnectionString('sqlite:///tmp/test.db'), 'sqlite');
});

test('driverTypeFromConnectionString: 无 scheme 的 .db 路径识别为 sqlite，其余回退 memory', () => {
  assert.equal(driverTypeFromConnectionString('/tmp/x.db'), 'sqlite');
  assert.equal(driverTypeFromConnectionString('data/foo.sqlite'), 'sqlite');
  assert.equal(driverTypeFromConnectionString(''), 'memory');
  assert.equal(driverTypeFromConnectionString('whatever text'), 'memory');
});

test('getDriver: 缺省 driverType 时按 connectionString 推断', async () => {
  // sqlite 推断 → SqlJsDriver（sql.js 已安装）或回退 MemoryRecordDriver；两者都是合法内置驱动
  const d = await getDriver({ db: { connectionString: 'sqlite://:memory:' } });
  assert.ok(
    d.constructor.name === 'SqlJsDriver' || d instanceof MemoryRecordDriver,
    `sqlite 推断应返回内置驱动（实得 ${d.constructor.name}）`
  );
  // 显式 memory 直达
  const d2 = await getDriver({ db: { connectionString: 'mysql://u:p@h/db', driverType: 'memory' } });
  assert.ok(d2 instanceof MemoryRecordDriver);
});

test('getDriver: 未注册真实驱动明确报错（防静默回退测试桩）', async () => {
  await assert.rejects(
    () => getDriver({ db: { connectionString: 'firebird://u:p@h/db', driverType: 'firebird' } }),
    /未注册/
  );
});

test('registerDriver: 注册后真实驱动工厂被调用并 connect', async () => {
  const calls = [];
  registerDriver('_test_drv', async (opts) => {
    calls.push(opts);
    return {
      async connect() { calls.push('connect'); },
      async query() { return { rows: [], columns: [] }; },
      async close() {},
    };
  });
  assert.ok(registeredDrivers().includes('_test_drv'));
  const d = await getDriver({ db: { connectionString: 'x://h/db', driverType: '_test_drv' } });
  assert.equal(calls.length, 2, '工厂 + connect 各调一次');
  assert.equal(calls[1], 'connect');
  assert.equal(d.constructor.name !== 'MemoryRecordDriver', true, '返回注册的驱动实例');
});
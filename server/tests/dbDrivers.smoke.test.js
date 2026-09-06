// DBMS 驱动注册冒烟测试
// 验证 registerDriver 接口工作正常，且真实驱动注册后可通过 getDriver 调用。
// 用 mock 驱动验证（Docker 不可用 + mysql2/pg/mssql 未安装）。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  driverTypeFromConnectionString,
  getDriver,
  registerDriver,
  registeredDrivers,
} from '../src/core/dbDrivers.js';

describe('DBMS 驱动注册冒烟测试', () => {
  test('registerDriver + getDriver: 注册 mock 驱动后可成功调用 query', async () => {
    registerDriver('_test_db', async (opts) => ({
      async connect() {},
      async query() {
        return { rows: [], columns: [] };
      },
      async close() {},
    }));

    const driver = await getDriver({
      db: { connectionString: 'x://h/db', driverType: '_test_db' },
    });
    assert.ok(driver, 'getDriver 应返回已注册的驱动实例');
    const result = await driver.query('SELECT 1');
    assert.deepEqual(result, { rows: [], columns: [] }, 'query 返回应符合契约');
  });

  test('driverTypeFromConnectionString: mysql:// → mysql', () => {
    assert.equal(driverTypeFromConnectionString('mysql://u:p@h/db'), 'mysql');
  });

  test('driverTypeFromConnectionString: postgres:// → postgres', () => {
    assert.equal(driverTypeFromConnectionString('postgres://u:p@h/db'), 'postgres');
  });

  test('driverTypeFromConnectionString: 空串 → memory', () => {
    assert.equal(driverTypeFromConnectionString(''), 'memory');
  });

  test('registeredDrivers: 包含 _test_db', () => {
    assert.ok(
      registeredDrivers().includes('_test_db'),
      '注册表应包含 _test_db'
    );
  });

  test('getDriver: 未注册 type 时抛出含"未注册"的清晰错误', async () => {
    await assert.rejects(
      () => getDriver({ db: { driverType: 'firebird' } }),
      /未注册/,
      '未注册的真实驱动应抛出含"未注册"的错误而非静默回退'
    );
  });
});

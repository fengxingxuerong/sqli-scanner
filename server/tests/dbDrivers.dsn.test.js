// [D184] DSN 结构化字段解析（dsnFields）与 getDriver 合并优先级测试。
// 背景：mysql://user:pass@host:port/db 的 userinfo 此前被静默丢弃——驱动拿默认 root + 空密码
// 去握手，MariaDB 10.11 真机实测报 auth_gssapi_client（见 CHANGELOG D184）。本组测试钉住：
//   1) dsnFields 纯解析：全形态 / percent-encode / 无 userinfo / 非 URL 容错；
//   2) getDriver 合并：DSN 字段进 db、显式 db 字段 > DSN > 驱动默认（只填缺失键）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dsnFields, getDriver, registerDriver } from '../src/core/dbDrivers.js';

test('dsnFields: 全形态 mysql://user:pass@host:port/db 五字段齐', () => {
  assert.deepEqual(dsnFields('mysql://scott:tiger@127.0.0.1:3306/sqli_lab'), {
    user: 'scott',
    password: 'tiger',
    host: '127.0.0.1',
    port: 3306,
    database: 'sqli_lab',
  });
});

test('dsnFields: percent-encode 凭据正确解码（@ / : 特殊字符）', () => {
  const f = dsnFields('mysql://u%40mail.com:p%3Ass@db.local/mydb');
  assert.equal(f.user, 'u@mail.com');
  assert.equal(f.password, 'p:ss');
});

test('dsnFields: 无 userinfo 不产生 user/password 键（零回归口径）', () => {
  const f = dsnFields('mysql://127.0.0.1:3306/test');
  assert.equal('user' in f, false);
  assert.equal('password' in f, false);
  assert.equal(f.host, '127.0.0.1');
  assert.equal(f.port, 3306);
  assert.equal(f.database, 'test');
});

test('dsnFields: 显式空密码 user:@host 视为未提供（驱动继续走 env 兑底）', () => {
  const f = dsnFields('mysql://user:@host/db');
  assert.equal('password' in f, false);
  assert.equal(f.user, 'user');
});

test('dsnFields: 非 URL 形态返回空对象（裸路径 / 纯文本 / 空串 / 非字符串）', () => {
  assert.deepEqual(dsnFields('/tmp/x.db'), {});
  assert.deepEqual(dsnFields('data/foo.sqlite'), {});
  assert.deepEqual(dsnFields('whatever text'), {});
  assert.deepEqual(dsnFields(''), {});
  assert.deepEqual(dsnFields(undefined), {});
});

test('dsnFields: 内置自检 DSN 不携带端口/路径键', () => {
  assert.deepEqual(dsnFields('pglite://memory'), { host: 'memory' });
  // sqlite://:memory: 的 authority 不合法 → 整体容错为空对象
  assert.deepEqual(dsnFields('sqlite://:memory:'), {});
});

test('getDriver: DSN 字段并入 db 传给驱动工厂（userinfo 不再丢失）', async () => {
  let captured = null;
  registerDriver('dsn-test-capture', async (o) => {
    captured = o;
    return { connect() {}, async query() { return { rows: [], columns: [] }; }, async close() {} };
  });
  await getDriver({ db: { connectionString: 'mysql://alice:secret@10.0.0.5:3307/mydb', driverType: 'dsn-test-capture' } });
  assert.equal(captured.user, 'alice');
  assert.equal(captured.password, 'secret');
  assert.equal(captured.host, '10.0.0.5');
  assert.equal(captured.port, 3307);
  assert.equal(captured.database, 'mydb');
});

test('getDriver: 显式 db 字段优先于 DSN 解析（只填缺失键）', async () => {
  let captured = null;
  registerDriver('dsn-test-precedence', async (o) => {
    captured = o;
    return { connect() {}, async query() { return { rows: [], columns: [] }; }, async close() {} };
  });
  await getDriver({ db: { connectionString: 'mysql://alice:secret@10.0.0.5:3307/mydb', driverType: 'dsn-test-precedence', user: 'bob' } });
  assert.equal(captured.user, 'bob');
  assert.equal(captured.password, 'secret');
});

test('getDriver: 无 userinfo 的旧形态行为不变（回归钉）', async () => {
  let captured = null;
  registerDriver('dsn-test-legacy', async (o) => {
    captured = o;
    return { connect() {}, async query() { return { rows: [], columns: [] }; }, async close() {} };
  });
  await getDriver({ db: { connectionString: 'mysql://127.0.0.1:3306/test', driverType: 'dsn-test-legacy' } });
  assert.equal('user' in captured, false);
  assert.equal('password' in captured, false);
  assert.equal(captured.host, '127.0.0.1');
  assert.equal(captured.port, 3306);
});

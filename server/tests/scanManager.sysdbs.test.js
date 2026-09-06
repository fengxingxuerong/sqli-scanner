// ScanManager 系统库过滤测试：dumpAllDatabases 前 MySQL/PG/SQLServer/Oracle
// 系统库被排除，dumpDatabase 不被系统库调用。
// 直接调用 _extract，mock extractor.enumerateDatabases 返回含系统库的列表，
// 断言 dumpDatabase 仅收到业务库。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';

function makeScanManager() {
  const sm = new ScanManager();
  return sm;
}

// 构造 mock extractor：enumerateDatabases 返回给定列表，dumpDatabase 记录被调用的 db 名
function mockExtractor(dbs) {
  const dumpedDbs = [];
  return {
    dumpedDbs,
    async enumerateDatabases() {
      return dbs.slice();
    },
    async enumerateTables() {
      return [];
    },
    async enumerateColumns() {
      return [];
    },
    async dumpDatabase(ctx, db) {
      dumpedDbs.push(db);
      return { tables: [], columns: {}, rows: {} };
    },
    async dumpAllDatabases(ctx, dbList) {
      // 真实 dumpAllDatabases 语义：对传入的 dbList 逐库调用 dumpDatabase
      for (const db of dbList) {
        await this.dumpDatabase(ctx, db);
      }
      return { databases: dbList, tables: {}, columns: {}, rows: {} };
    },
    setColumnTypeEnumerator() {},
    extractProof: async () => null,
  };
}

function buildCtx(dbms = 'MySQL', excludeSysdbs = true) {
  return {
    httpClient: { async request() { return { data: '', status: 200 }; }, removeBucket() {} },
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: { excludeSysdbs, timeoutMs: 5000, retry: 0 },
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1' },
    dbms,
    config: { excludeSysdbs, timeoutMs: 5000, retry: 0 },
  };
}

test('MySQL: 系统库 mysql/information_schema/performance_schema/sys 被过滤', async () => {
  const sm = makeScanManager();
  const dbs = ['myapp', 'mysql', 'information_schema', 'performance_schema', 'sys', 'shop'];
  const mock = mockExtractor(dbs);
  sm.extractor = mock;
  sm.exploiter = { deepDump: async () => [] };
  sm.colTypeEnum = null;

  const data = await sm._extract('test-scan-mysql', buildCtx('MySQL'));

  // 系统库不在 dumpDatabase 调用列表里
  for (const sysdb of ['mysql', 'information_schema', 'performance_schema', 'sys']) {
    assert.ok(!mock.dumpedDbs.includes(sysdb), `系统库 ${sysdb} 不应被 dump`);
  }
  // 业务库被 dump
  assert.ok(mock.dumpedDbs.includes('myapp'), '业务库 myapp 应被 dump');
  assert.ok(mock.dumpedDbs.includes('shop'), '业务库 shop 应被 dump');
  // data.databases 仅含业务库
  assert.deepEqual(data.databases.sort(), ['myapp', 'shop']);
});

test('PostgreSQL: 系统库 pg_catalog/pg_toast/information_schema 被过滤', async () => {
  const sm = makeScanManager();
  const dbs = ['webapp', 'pg_catalog', 'pg_toast', 'information_schema', 'analytics'];
  const mock = mockExtractor(dbs);
  sm.extractor = mock;
  sm.exploiter = { deepDump: async () => [] };
  sm.colTypeEnum = null;

  const data = await sm._extract('test-scan-pg', buildCtx('PostgreSQL'));

  for (const sysdb of ['pg_catalog', 'pg_toast', 'information_schema']) {
    assert.ok(!mock.dumpedDbs.includes(sysdb), `系统库 ${sysdb} 不应被 dump`);
  }
  assert.ok(mock.dumpedDbs.includes('webapp'), '业务库 webapp 应被 dump');
  assert.deepEqual(data.databases.sort(), ['analytics', 'webapp']);
});

test('SQL Server: 系统库 master/model/msdb/tempdb 被过滤', async () => {
  const sm = makeScanManager();
  const dbs = ['appdb', 'master', 'model', 'msdb', 'tempdb', 'reportdb'];
  const mock = mockExtractor(dbs);
  sm.extractor = mock;
  sm.exploiter = { deepDump: async () => [] };
  sm.colTypeEnum = null;

  const data = await sm._extract('test-scan-mssql', buildCtx('SQL Server'));

  for (const sysdb of ['master', 'model', 'msdb', 'tempdb']) {
    assert.ok(!mock.dumpedDbs.includes(sysdb), `系统库 ${sysdb} 不应被 dump`);
  }
  assert.deepEqual(data.databases.sort(), ['appdb', 'reportdb']);
});

test('Oracle: 系统 schema sys/system 被过滤', async () => {
  const sm = makeScanManager();
  const dbs = ['HR', 'SYS', 'SYSTEM', 'SALES'];
  const mock = mockExtractor(dbs);
  sm.extractor = mock;
  sm.exploiter = { deepDump: async () => [] };
  sm.colTypeEnum = null;

  const data = await sm._extract('test-scan-oracle', buildCtx('Oracle'));

  for (const sysdb of ['SYS', 'SYSTEM']) {
    assert.ok(!mock.dumpedDbs.includes(sysdb), `系统 schema ${sysdb} 不应被 dump`);
  }
  assert.deepEqual(data.databases.sort(), ['HR', 'SALES']);
});

test('excludeSysdbs=false: 系统库不被过滤', async () => {
  const sm = makeScanManager();
  const dbs = ['myapp', 'mysql', 'information_schema'];
  const mock = mockExtractor(dbs);
  sm.extractor = mock;
  sm.exploiter = { deepDump: async () => [] };
  sm.colTypeEnum = null;

  const data = await sm._extract('test-scan-nofilter', buildCtx('MySQL', false));

  // 系统库也被 dump
  assert.ok(mock.dumpedDbs.includes('mysql'), 'excludeSysdbs=false 时 mysql 应被 dump');
  assert.ok(mock.dumpedDbs.includes('information_schema'), 'excludeSysdbs=false 时 information_schema 应被 dump');
  assert.deepEqual(data.databases.sort(), ['information_schema', 'myapp', 'mysql']);
});

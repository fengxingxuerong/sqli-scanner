// SYS_QUERIES 数据字典扩展回归
// 通过 mock httpClient 捕获实际发送的 SQL，验证：
//   1) Oracle databases 从 null → 发送含 all_users 的 SQL（可枚举 schema）
//   2) ClickHouse 全链存在（system.databases / system.tables / system.columns）
//   3) DB2 全链存在（SYSCAT.TABLES / SYSCAT.COLUMNS）
//   4) HSQLDB/Derby 全链存在（INFORMATION_SCHEMA / SYS.SYSTABLES）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

// 捕获最后一次发送的 SQL 的 mock httpClient
function captureClient() {
  let lastSql = '';
  const client = {
    async request(opts) {
      // 从 url query 或 body 提取注入值（含 SQL）
      const url = String(opts?.url || '');
      const m = url.match(/[?&]q=([^&]*)/);
      if (m) lastSql = decodeURIComponent(m[1]).replace(/\+/g, ' ');
      else if (opts?.data && typeof opts.data === 'object') lastSql = String(Object.values(opts.data)[0] || '');
      else lastSql = String(opts?.data || '');
      return { status: 200, headers: {}, data: '__S__result__E__' };
    },
  };
  return { client, getLastSql: () => lastSql };
}

function makeCtx(dbms) {
  return {
    httpClient: null, // 由 captureClient 注入
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: {
      id: 'p1', location: 'url', param: 'q', originalValue: '1',
      confirmed: false, echoCols: [0], columns: 1, boundary: '',
    },
    dbms,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

test('Oracle: enumerateDatabases 发送含 all_users 的 SQL（此前 null→空）', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('Oracle'), httpClient: client };
  await ex.enumerateDatabases(ctx);
  const sql = getLastSql();
  assert.ok(sql.includes('all_users'), `Oracle databases SQL 应含 all_users（实发: ${sql.slice(0, 80)}）`);
});

test('ClickHouse: enumerateDatabases 发送 system.databases SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('ClickHouse'), httpClient: client };
  await ex.enumerateDatabases(ctx);
  assert.ok(getLastSql().includes('system.databases'), '应含 system.databases');
});

test('ClickHouse: enumerateTables 发送 system.tables SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('ClickHouse'), httpClient: client };
  await ex.enumerateTables(ctx, 'mydb');
  assert.ok(getLastSql().includes('system.tables'), '应含 system.tables');
});

test('ClickHouse: enumerateColumns 发送 system.columns SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('ClickHouse'), httpClient: client };
  await ex.enumerateColumns(ctx, 'mydb', 'mytable');
  assert.ok(getLastSql().includes('system.columns'), '应含 system.columns');
});

test('DB2: enumerateTables 发送 SYSCAT.TABLES SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('DB2'), httpClient: client };
  await ex.enumerateTables(ctx, 'DB');
  assert.ok(getLastSql().includes('SYSCAT.TABLES'), '应含 SYSCAT.TABLES');
});

test('HSQLDB: enumerateTables 发送 INFORMATION_SCHEMA SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('HSQLDB'), httpClient: client };
  await ex.enumerateTables(ctx, 'PUBLIC');
  assert.ok(getLastSql().includes('INFORMATION_SCHEMA'), '应含 INFORMATION_SCHEMA');
});

test('Derby: enumerateTables 发送 SYS.SYSTABLES SQL', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('Derby'), httpClient: client };
  await ex.enumerateTables(ctx, 'APP');
  assert.ok(getLastSql().includes('SYS.SYSTABLES'), '应含 SYS.SYSTABLES');
});

test('MySQL 回归: enumerateDatabases 发送 information_schema.schemata', async () => {
  const { client, getLastSql } = captureClient();
  const ctx = { ...makeCtx('MySQL'), httpClient: client };
  await ex.enumerateDatabases(ctx);
  assert.ok(getLastSql().includes('information_schema.schemata'), 'MySQL 仍用 information_schema.schemata');
});
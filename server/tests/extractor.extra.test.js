// Extractor 额外 5 项 sqlmap 对标参数测试：hostname / isDba / schema / privileges / roles
// 用 mock httpClient 捕获注入值，断言各方言 SQL 片段正确包含。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

// 从注入请求里还原注入值：支持 url query / body / cookie 三位置
function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  if (opts.headers && opts.headers.Cookie) {
    const m = opts.headers.Cookie.match(/q=([^;]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// 捕获每次请求的注入值，返回 __S__value__E__ 作为回显
function makeCaptureOracle(captured) {
  return {
    async request(opts) {
      const v = extractQuery(opts);
      captured.push(v);
      return { data: 'prefix __S__value__E__ suffix', status: 200 };
    },
  };
}

function buildCtx(httpClient, dbms = 'MySQL') {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', echoCols: [1], confirmed: true },
    dbms,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

// ─────────────── enumerateHostname ───────────────
test('enumerateHostname(MySQL) payload 含 @@hostname', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateHostname(ctx);
  const sql = cap.find((v) => v.includes('@@hostname')) || '';
  assert.ok(/@@hostname/i.test(sql), `期望含 @@hostname，实际: ${sql}`);
});

test('enumerateHostname(PostgreSQL) payload 含 inet_server_addr', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateHostname(ctx);
  const sql = cap.find((v) => v.includes('inet_server_addr')) || '';
  assert.ok(/inet_server_addr/i.test(sql), `期望含 inet_server_addr，实际: ${sql}`);
});

test('enumerateHostname(SQL Server) payload 含 @@SERVERNAME', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumerateHostname(ctx);
  const sql = cap.find((v) => v.includes('@@SERVERNAME')) || '';
  assert.ok(/@@SERVERNAME/i.test(sql), `期望含 @@SERVERNAME，实际: ${sql}`);
});

test('enumerateHostname(Oracle) payload 含 SYS_CONTEXT(...HOST)', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'Oracle');
  await ex.enumerateHostname(ctx);
  const sql = cap.find((v) => v.includes('SYS_CONTEXT')) || '';
  assert.ok(/SYS_CONTEXT\(/i.test(sql), `期望含 SYS_CONTEXT(，实际: ${sql}`);
  assert.ok(/HOST/i.test(sql), `期望含 HOST，实际: ${sql}`);
});

test('enumerateHostname(ClickHouse) payload 含 hostName()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'ClickHouse');
  await ex.enumerateHostname(ctx);
  const sql = cap.find((v) => v.includes('hostName')) || '';
  assert.ok(/hostName\(\)/i.test(sql), `期望含 hostName()，实际: ${sql}`);
});

test('enumerateHostname(SQLite) 返回 null', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const result = await ex.enumerateHostname(ctx);
  assert.equal(result, null);
});

// ─────────────── enumerateIsDba ───────────────
test('enumerateIsDba(MySQL) payload 含 super_priv', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateIsDba(ctx);
  const sql = cap.find((v) => v.includes('super_priv')) || '';
  assert.ok(/super_priv/i.test(sql), `期望含 super_priv，实际: ${sql}`);
});

test('enumerateIsDba(PostgreSQL) payload 含 is_superuser', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateIsDba(ctx);
  const sql = cap.find((v) => v.includes('is_superuser')) || '';
  assert.ok(/is_superuser/i.test(sql), `期望含 is_superuser，实际: ${sql}`);
});

test('enumerateIsDba(SQL Server) payload 含 IS_SRVROLEMEMBER', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumerateIsDba(ctx);
  const sql = cap.find((v) => v.includes('IS_SRVROLEMEMBER')) || '';
  assert.ok(/IS_SRVROLEMEMBER/i.test(sql), `期望含 IS_SRVROLEMEMBER，实际: ${sql}`);
});

test('enumerateIsDba(Oracle) payload 含 session_privs', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'Oracle');
  await ex.enumerateIsDba(ctx);
  const sql = cap.find((v) => v.includes('session_privs')) || '';
  assert.ok(/session_privs/i.test(sql), `期望含 session_privs，实际: ${sql}`);
});

test('enumerateIsDba(SQLite) 返回 null', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const result = await ex.enumerateIsDba(ctx);
  assert.equal(result, null);
});

// ─────────────── enumerateSchema ───────────────
test('enumerateSchema(MySQL) payload 含 information_schema.COLUMNS', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateSchema(ctx, 'mydb', 'users');
  const sql = cap.find((v) => v.includes('information_schema')) || '';
  assert.ok(/information_schema\.COLUMNS/i.test(sql), `期望含 information_schema.COLUMNS，实际: ${sql}`);
  assert.ok(/COLUMN_NAME/.test(sql), `期望含 COLUMN_NAME，实际: ${sql}`);
  assert.ok(/COLUMN_TYPE/.test(sql), `期望含 COLUMN_TYPE，实际: ${sql}`);
});

test('enumerateSchema(PostgreSQL) payload 含 information_schema.columns', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateSchema(ctx, 'public', 'users');
  const sql = cap.find((v) => v.includes('information_schema.columns')) || '';
  assert.ok(/information_schema\.columns/i.test(sql), `期望含 information_schema.columns，实际: ${sql}`);
});

test('enumerateSchema(SQLite) payload 含 pragma_table_info', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  await ex.enumerateSchema(ctx, null, 'users');
  const sql = cap.find((v) => v.includes('pragma_table_info')) || '';
  assert.ok(/pragma_table_info/i.test(sql), `期望含 pragma_table_info，实际: ${sql}`);
});

test('enumerateSchema(Oracle) payload 含 user_tab_columns', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'Oracle');
  await ex.enumerateSchema(ctx, null, 'users');
  const sql = cap.find((v) => v.includes('user_tab_columns')) || '';
  assert.ok(/user_tab_columns/i.test(sql), `期望含 user_tab_columns，实际: ${sql}`);
});

// ─────────────── enumerateUserPrivs ───────────────
test('enumerateUserPrivs(MySQL) payload 含 user_privileges', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateUserPrivs(ctx);
  const sql = cap.find((v) => v.includes('user_privileges')) || '';
  assert.ok(/user_privileges/i.test(sql), `期望含 user_privileges，实际: ${sql}`);
});

test('enumerateUserPrivs(PostgreSQL) payload 含 role_table_grants', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateUserPrivs(ctx);
  const sql = cap.find((v) => v.includes('role_table_grants')) || '';
  assert.ok(/role_table_grants/i.test(sql), `期望含 role_table_grants，实际: ${sql}`);
});

test('enumerateUserPrivs(SQL Server) payload 含 fn_my_permissions', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumerateUserPrivs(ctx);
  const sql = cap.find((v) => v.includes('fn_my_permissions')) || '';
  assert.ok(/fn_my_permissions/i.test(sql), `期望含 fn_my_permissions，实际: ${sql}`);
});

test('enumerateUserPrivs(SQLite) 返回 null', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const result = await ex.enumerateUserPrivs(ctx);
  assert.equal(result, null);
});

// ─────────────── enumerateRoles ───────────────
test('enumerateRoles(MySQL) payload 含 GRANTEE', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateRoles(ctx);
  const sql = cap.find((v) => v.includes('GRANTEE')) || '';
  assert.ok(/GRANTEE/i.test(sql), `期望含 GRANTEE，实际: ${sql}`);
});

test('enumerateRoles(PostgreSQL) payload 含 pg_roles', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateRoles(ctx);
  const sql = cap.find((v) => v.includes('pg_roles')) || '';
  assert.ok(/pg_roles/i.test(sql), `期望含 pg_roles，实际: ${sql}`);
});

test('enumerateRoles(SQL Server) payload 含 database_principals', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumerateRoles(ctx);
  const sql = cap.find((v) => v.includes('database_principals')) || '';
  assert.ok(/database_principals/i.test(sql), `期望含 database_principals，实际: ${sql}`);
});

test('enumerateRoles(SQLite) 返回 null', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const result = await ex.enumerateRoles(ctx);
  assert.equal(result, null);
});
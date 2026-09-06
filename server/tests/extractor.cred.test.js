// 凭据收割测试（对标 sqlmap --users/--passwords）：
// 用 mock httpClient 捕获注入 payload，断言 MySQL users/passwords 的 SQL
// 含 mysql.user 与 authentication_string，且其余方言查询结构正确。
// enumerateUsers/enumeratePasswords 查询失败时返回 null（不阻断）。
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

// 捕获每次请求的注入值，回显 __S__value__E__ 模拟 UNION 回显点带出标量
function makeCaptureOracle(captured) {
  return {
    async request(opts) {
      const v = extractQuery(opts);
      captured.push(v);
      return { data: `prefix __S__value__E__ suffix`, status: 200 };
    },
  };
}

// 失败 oracle：所有请求返回 null（模拟权限不足/查询失败）
function makeFailOracle() {
  return {
    async request() {
      return null;
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

// —— MySQL users ——
test('MySQL: enumerateUsers payload 含 mysql.user 与 CONCAT(user,0x40,host)', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumerateUsers(ctx);
  const sql = cap.find((v) => v.includes('mysql.user')) || '';
  assert.ok(sql.includes('mysql.user'), `期望含 mysql.user，实际: ${sql}`);
  assert.ok(/CONCAT\(user,0x40,host\)/i.test(sql), `期望含 CONCAT(user,0x40,host)，实际: ${sql}`);
});

// —— MySQL passwords ——
test('MySQL: enumeratePasswords payload 含 mysql.user 与 authentication_string', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.enumeratePasswords(ctx);
  const sql = cap.find((v) => v.includes('mysql.user')) || '';
  assert.ok(sql.includes('mysql.user'), `期望含 mysql.user，实际: ${sql}`);
  assert.ok(
    /authentication_string/i.test(sql),
    `期望含 authentication_string，实际: ${sql}`
  );
  assert.ok(/IFNULL/i.test(sql), `期望含 IFNULL（兼容旧版 password 列），实际: ${sql}`);
});

// —— PostgreSQL users ——
test('PostgreSQL: enumerateUsers payload 含 pg_user 与 string_agg(usename)', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumerateUsers(ctx);
  const sql = cap.find((v) => v.includes('pg_user')) || '';
  assert.ok(sql.includes('pg_user'), `期望含 pg_user，实际: ${sql}`);
  assert.ok(/string_agg\(usename/i.test(sql), `期望含 string_agg(usename)，实际: ${sql}`);
});

// —— PostgreSQL passwords ——
test('PostgreSQL: enumeratePasswords payload 含 pg_shadow 与 passwd', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.enumeratePasswords(ctx);
  const sql = cap.find((v) => v.includes('pg_shadow')) || '';
  assert.ok(sql.includes('pg_shadow'), `期望含 pg_shadow，实际: ${sql}`);
  assert.ok(/passwd/i.test(sql), `期望含 passwd，实际: ${sql}`);
});

// —— SQL Server users ——
test('SQL Server: enumerateUsers payload 含 sys.sql_logins', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumerateUsers(ctx);
  const sql = cap.find((v) => v.includes('sql_logins')) || '';
  assert.ok(sql.includes('sys.sql_logins'), `期望含 sys.sql_logins，实际: ${sql}`);
  assert.ok(/string_agg\(name/i.test(sql), `期望含 string_agg(name)，实际: ${sql}`);
});

// —— SQL Server passwords ——
test('SQL Server: enumeratePasswords payload 含 password_hash 与 fn_varbintohexstr', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.enumeratePasswords(ctx);
  const sql = cap.find((v) => v.includes('sql_logins')) || '';
  assert.ok(sql.includes('sys.sql_logins'), `期望含 sys.sql_logins，实际: ${sql}`);
  assert.ok(/password_hash/i.test(sql), `期望含 password_hash，实际: ${sql}`);
  assert.ok(
    /fn_varbintohexstr/i.test(sql),
    `期望含 fn_varbintohexstr，实际: ${sql}`
  );
});

// —— 查询失败返回 null（权限不足不阻断）——
test('MySQL: enumerateUsers 查询失败返回 null（不阻断）', async () => {
  const ctx = buildCtx(makeFailOracle(), 'MySQL');
  const val = await ex.enumerateUsers(ctx);
  assert.equal(val, null);
});

test('MySQL: enumeratePasswords 查询失败返回 null（不阻断）', async () => {
  const ctx = buildCtx(makeFailOracle(), 'MySQL');
  const val = await ex.enumeratePasswords(ctx);
  assert.equal(val, null);
});

// —— 不支持的方言返回 null（无 users/passwords 查询模板）——
test('SQLite: enumerateUsers 无模板返回 null', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const val = await ex.enumerateUsers(ctx);
  assert.equal(val, null);
  assert.equal(cap.length, 0, 'SQLite 无 users 模板不应发请求');
});

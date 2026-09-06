// Extractor 元能力测试：currentDb / currentUser / countRows 发出的 UNION payload
// 包含各方言正确的查询表达式。用 mock httpClient 捕获注入值，断言 SQL 片段存在。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

// 从注入请求里还原注入值：支持 url query / body / cookie 三位置（与 extractor.test 同构）
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

// 捕获每次请求的注入值，返回 __S__<value>__E__ 作为回显，模拟 UNION 回显点带出标量
function makeCaptureOracle(captured) {
  return {
    async request(opts) {
      const v = extractQuery(opts);
      captured.push(v);
      // 回显：extractScalar 用 __S__/__E__ 标记包裹表达式结果，这里回放同名标记便于命中正则
      return { data: `prefix __S__value__E__ suffix`, status: 200 };
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

test('currentDb(MySQL) payload 含 database()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.currentDb(ctx);
  const sql = cap.find((v) => v.includes('database')) || '';
  assert.ok(/database\(\)/i.test(sql), `期望含 database()，实际: ${sql}`);
});

test('currentUser(MySQL) payload 含 current_user()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.currentUser(ctx);
  const sql = cap.find((v) => v.includes('current_user')) || '';
  assert.ok(/current_user\(\)/i.test(sql), `期望含 current_user()，实际: ${sql}`);
});

test('countRows(MySQL) payload 含 COUNT(*) 且表名反引号转义', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'MySQL');
  await ex.countRows(ctx, 'mydb', 'users');
  const sql = cap.find((v) => v.includes('COUNT')) || '';
  assert.ok(/COUNT\(\*\)/i.test(sql), `期望含 COUNT(*)，实际: ${sql}`);
  assert.ok(/`mydb`\.`users`/.test(sql), `期望含 \`mydb\`.\`users\`，实际: ${sql}`);
});

test('currentDb(PostgreSQL) payload 含 current_database()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.currentDb(ctx);
  const sql = cap.find((v) => v.includes('current_database')) || '';
  assert.ok(/current_database\(\)/i.test(sql), `期望含 current_database()，实际: ${sql}`);
});

test('currentUser(PostgreSQL) payload 含 current_user 标识符', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'PostgreSQL');
  await ex.currentUser(ctx);
  const sql = cap.find((v) => v.includes('current_user')) || '';
  assert.ok(/\bcurrent_user\b/i.test(sql), `期望含 current_user，实际: ${sql}`);
});

test('currentDb(SQL Server) payload 含 DB_NAME()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQL Server');
  await ex.currentDb(ctx);
  const sql = cap.find((v) => v.includes('DB_NAME')) || '';
  assert.ok(/DB_NAME\(\)/i.test(sql), `期望含 DB_NAME()，实际: ${sql}`);
});

test('currentDb(Oracle) payload 含 SYS_CONTEXT(...DB_NAME)', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'Oracle');
  await ex.currentDb(ctx);
  const sql = cap.find((v) => v.includes('SYS_CONTEXT')) || '';
  assert.ok(/SYS_CONTEXT\(/i.test(sql), `期望含 SYS_CONTEXT(，实际: ${sql}`);
  assert.ok(/DB_NAME/i.test(sql), `期望含 DB_NAME，实际: ${sql}`);
});

test('currentDb(ClickHouse) payload 含 currentDatabase()', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'ClickHouse');
  await ex.currentDb(ctx);
  const sql = cap.find((v) => v.includes('currentDatabase')) || '';
  assert.ok(/currentDatabase\(\)/i.test(sql), `期望含 currentDatabase()，实际: ${sql}`);
});

test('currentDb(SQLite) 返回 null（无会话库概念）', async () => {
  const cap = [];
  const ctx = buildCtx(makeCaptureOracle(cap), 'SQLite');
  const r = await ex.currentDb(ctx);
  assert.equal(r, null, 'SQLite currentDb 应返回 null');
  assert.equal(cap.length, 0, 'SQLite currentDb 不应发请求');
});

test('countRows 返回数字类型（回显 value）', async () => {
  // 回显 42 作为 COUNT 结果
  const oracle = {
    async request(_opts) {
      return { data: `__S__42__E__`, status: 200 };
    },
  };
  const ctx = buildCtx(oracle, 'MySQL');
  const n = await ex.countRows(ctx, 'mydb', 'users');
  assert.equal(n, 42, 'countRows 应返回数字 42');
  assert.equal(typeof n, 'number');
});

// Extractor 盲注二分提取 + ColumnTypeEnumerator 单元测试
// 使用"布尔预言机" mock httpClient 模拟已知 secret 的数据库，验证二分逐字符逻辑。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { ColumnTypeEnumerator } from '../src/engine/ColumnTypeEnumerator.js';

// 从请求中取出注入值（detector/extractor 把注入值放到 url query / body / cookie）
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

// 构造布尔预言机：已知 secret 字符串，注入条件为真时返回非空响应
function makeBooleanOracle(secret) {
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      // 长度探测：(LENGTH((X)))>N 或 (LEN((X)))>N（外层括号由 makeCond 包裹，用 )+ 兼容）
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) {
        return { data: Number(lenM[1]) < secret.length ? 'OK' : '', status: 200 };
      }
      // 字符探测：ASCII(SUBSTRING((X),i,1))>C 或 SUBSTR
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        const code = secret.charCodeAt(i - 1);
        return { data: c < code ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, dbms = 'MySQL') {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

test('extractBoolean 二分逐字符提取版本字符串', async () => {
  const secret = '5.7.40';
  const ctx = buildCtx(makeBooleanOracle(secret), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
});

test('extractBoolean 长度探测为 0 时返回 null', async () => {
  const ctx = buildCtx(makeBooleanOracle(''), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, null);
});

test('extractProof 返回版本证明字符串', async () => {
  const secret = '8.0.33';
  const ctx = buildCtx(makeBooleanOracle(secret), 'MySQL');
  const proof = await ex.extractProof(ctx);
  assert.equal(proof, secret);
});

test('extractScalar 从 UNION 回显中提取标记间内容', async () => {
  // mock httpClient：模拟数据库把 version() 求值后回显在 __S__...__E__ 之间
  const mock = {
    async request(opts) {
      const q = extractQuery(opts);
      if (/__S__/.test(q)) return { data: '__S__5.7.40__E__', status: 200 };
      return { data: 'nomatch', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL');
  const val = await ex.extractScalar(ctx, 'version()', 3);
  // extractScalar 把 version() 包进 WRAP 后放在第 2 列，回显 __S__5.7.40__E__
  assert.equal(val, '5.7.40');
});

test('guessColumns 线性探测返回列数', async () => {
  // mock：ORDER BY 超过 3 列时返回短响应
  const mock = {
    async request(opts) {
      const q = extractQuery(opts);
      if (/ORDER BY (\d+)/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return { data: n > 3 ? 'ERR' : 'okresult', status: n > 3 ? 500 : 200 };
      }
      return { data: 'baseline', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL');
  const cols = await ex.guessColumns(ctx);
  assert.equal(cols, 3);
});

test('ColumnTypeEnumerator 通过 extractor 枚举列类型', async () => {
  const localEx = new Extractor();
  localEx.extractScalar = async () => 'int,varchar,text';
  localEx.guessColumns = async () => 3;
  const cte = new ColumnTypeEnumerator();
  const ctx = { dbms: 'MySQL', extractor: localEx, target: {}, point: {}, config: {} };
  const typed = await cte.enumerate(ctx, 'testdb', 'users', ['id', 'name', 'bio']);
  assert.deepEqual(typed, [
    { name: 'id', type: 'int' },
    { name: 'name', type: 'varchar' },
    { name: 'bio', type: 'text' },
  ]);
});

test('ColumnTypeEnumerator extractor 为 null 时返回 unknown', async () => {
  const cte = new ColumnTypeEnumerator();
  const ctx = { dbms: 'MySQL', extractor: null, target: {}, point: {}, config: {} };
  const typed = await cte.enumerate(ctx, 'db', 't', ['a', 'b']);
  assert.deepEqual(typed, [
    { name: 'a', type: 'unknown' },
    { name: 'b', type: 'unknown' },
  ]);
});

test('extractBoolean 长字符串并发多字符提取正确（长度>并发度，强制多轮）', async () => {
  const secret = '8.0.33-MariaDB-0ubuntu0.20.04.1-log';
  const ctx = buildCtx(makeBooleanOracle(secret), 'MySQL');
  ctx.config.extractConcurrency = 3; // 故意小于长度，强制多轮并发分批
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
});

test('guessColumns 二分探测返回列数（与线性等价）', async () => {
  const mock = {
    async request(opts) {
      const q = extractQuery(opts);
      if (/ORDER BY (\d+)/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return { data: n > 3 ? 'ERR' : 'okresult', status: n > 3 ? 500 : 200 };
      }
      return { data: 'baseline', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL');
  const cols = await ex.guessColumns(ctx);
  assert.equal(cols, 3);
});

// v7：dumpData 分页续拉（MySQL 支持 LIMIT/OFFSET，自动续拉到全量）
function makePager(totalRows) {
  const rows = Array.from({ length: totalRows }, (_, i) => `${i + 1}|user${i + 1}`);
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (/__S__/.test(q)) {
        const offM = q.match(/OFFSET (\d+)/);
        const offset = offM ? Number(offM[1]) : 0;
        const limM = q.match(/LIMIT (\d+)/);
        const lim = limM ? Number(limM[1]) : 100;
        const page = rows.slice(offset, offset + lim);
        return { data: `__S__${page.join('||')}__E__`, status: 200 };
      }
      if (/ORDER BY (\d+)/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return { data: n > 3 ? 'ERR' : 'baseline', status: n > 3 ? 500 : 200 };
      }
      return { data: 'baseline', status: 200 };
    },
  };
}

test('dumpData 分页续拉合并多页到全量（MySQL，每页2行共5行→3页）', async () => {
  const ctx = buildCtx(makePager(5), 'MySQL');
  ctx.point.echoCols = [0]; // 跳过 discoverEchoColumns 探测
  const rows = await ex.dumpData(ctx, 'testdb', 'users', ['id', 'name'], 2);
  assert.equal(rows.length, 5);
  assert.deepEqual(rows[0], { id: '1', name: 'user1' });
  assert.deepEqual(rows[4], { id: '5', name: 'user5' });
});

test('dumpData Oracle 单页（ROWNUM 限制，不续拉）', async () => {
  const mock = {
    async request(opts) {
      const q = extractQuery(opts);
      if (/__S__/.test(q)) return { data: '__S__1|user1||2|user2__E__', status: 200 };
      return { data: 'baseline', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'Oracle');
  ctx.point.echoCols = [0];
  const rows = await ex.dumpData(ctx, 'testdb', 'users', ['id', 'name'], 100);
  assert.equal(rows.length, 2); // Oracle 单页，不续拉
});

test('_guessColumnsCached 缓存列数，避免重复 ORDER BY 二分探测', async () => {
  let orderByCount = 0;
  const mock = {
    async request(opts) {
      const q = extractQuery(opts);
      if (/ORDER BY (\d+)/.test(q)) {
        orderByCount++;
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return { data: n > 3 ? 'ERR' : 'baseline', status: n > 3 ? 500 : 200 };
      }
      return { data: 'baseline', status: 200 };
    },
  };
  const ctx = buildCtx(mock, 'MySQL');
  const c1 = await ex._guessColumnsCached(ctx);
  const c2 = await ex._guessColumnsCached(ctx); // 第二次应命中缓存
  assert.equal(c1, 3);
  assert.equal(c2, 3);
  assert.equal(orderByCount, 4); // 二分 1..10 约 4 次；第二次调用 0 次新增
});

function makeMultiTable() {
  const tableRows = {
    t1: ['r1a|r1b', 'r2a|r2b'],
    t2: ['s1a|s1b'],
    t3: ['u1a|u1b', 'u2a|u2b', 'u3a|u3b'],
  };
  let inFlight = 0;
  let peak = 0;
  return {
    peak: () => peak,
    async request(opts) {
      const q = extractQuery(opts);
      inFlight++;
      peak = Math.max(peak, inFlight);
      await Promise.resolve(); // 让出事件循环，使并发请求能在途叠加（模拟真实异步 IO），便于观测在途峰值
      try {
        if (/GROUP_CONCAT\(table_name/.test(q)) return { data: '__S__t1,t2,t3__E__', status: 200 };
        if (/GROUP_CONCAT\(column_name/.test(q)) return { data: '__S__a,b__E__', status: 200 };
        if (/FROM `testdb`\.`(\w+)`/.test(q)) {
          const t = q.match(/FROM `testdb`\.`(\w+)`/)[1];
          return { data: `__S__${(tableRows[t] || []).join('||')}__E__`, status: 200 };
        }
        return { data: 'baseline', status: 200 };
      } finally {
        inFlight--;
      }
    },
  };
}

test('dumpDatabase 表级并发拖库（多表同时 dump，结果聚合正确）', async () => {
  const mock = makeMultiTable();
  const ctx = buildCtx(mock, 'MySQL');
  ctx.point.echoCols = [0];
  ctx.config.dumpConcurrency = 3;
  const res = await ex.dumpDatabase(ctx, 'testdb');
  assert.deepEqual(res.tables.sort(), ['t1', 't2', 't3']);
  assert.equal(res.rows.t1.length, 2);
  assert.deepEqual(res.rows.t1[0], { a: 'r1a', b: 'r1b' });
  assert.equal(res.rows.t2.length, 1);
  assert.equal(res.rows.t3.length, 3);
  // 三表并发启动，在途请求峰值应 >1，证明非全串行
  assert.ok(mock.peak() >= 2, `期望并发，实际峰值=${mock.peak()}`);
});

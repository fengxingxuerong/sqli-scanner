// 主动语法探针指纹（DBFingerprinter.probeSyntaxFingerprint）单元测试
// 覆盖：各 DBMS 的 TRUE 探针≈基线即命中、非命中库（状态码偏离/长度骤变）被排除、
// 全错返回 null、以及完整 fingerprint() 在无 UNION 回显列时回落到语法探针。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';
import { createTarget } from '../src/engine/models.js';

// 各库的专属判别 token（探针里出现该串即代表"该库能解析此语法"）
const TOKEN = {
  SQLite: 'sqlite_version',
  MySQL: 'CONNECTION_ID',
  MariaDB: 'CONNECTION_ID', // 与 MySQL 共用探针，无法靠本方法区分
  PostgreSQL: 'current_database',
  'SQL Server': 'ISNULL',
  Oracle: 'all_tables',
};

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// 模拟目标：仅当探针命中 targetDbms 的专属 token 时返回与基线一致的良性响应，
// 其余探针一律返回错误（状态码偏离或长度骤变）→ 被排除。忠实还原"非命中库语法错误"。
function makeSyntaxMock(targetDbms) {
  const tok = TOKEN[targetDbms];
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (tok && q.includes(tok)) return { status: 200, data: 'normal' }; // ≈基线
      // 偏离基线：5xx 错误页 + 长度与基线("normal"=6)差距巨大
      return { status: 500, data: 'SQL syntax error near near near near near near near' };
    },
  };
}

function syntaxCtx(targetDbms, config = {}) {
  const target = createTarget({ url: 'http://mock/?q=1' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null };
  return { httpClient: makeSyntaxMock(targetDbms), target, point, config };
}

const BASELINE = { status: 200, headers: {}, body: 'normal' }; // 基线体长 = 6

// ===== 直接单元测试 probeSyntaxFingerprint =====

test('语法探针：SQLite 目标 → 返回 SQLite', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.probeSyntaxFingerprint(syntaxCtx('SQLite'), BASELINE);
  assert.equal(res, 'SQLite');
});

test('语法探针：PostgreSQL 目标 → 返回 PostgreSQL', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.probeSyntaxFingerprint(syntaxCtx('PostgreSQL'), BASELINE);
  assert.equal(res, 'PostgreSQL');
});

test('语法探针：SQL Server 目标 → 返回 SQL Server（ISNULL 双参排他对 MySQL）', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.probeSyntaxFingerprint(syntaxCtx('SQL Server'), BASELINE);
  assert.equal(res, 'SQL Server');
});

test('语法探针：Oracle 目标 → 返回 Oracle', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.probeSyntaxFingerprint(syntaxCtx('Oracle'), BASELINE);
  assert.equal(res, 'Oracle');
});

test('语法探针：MySQL 目标 → 返回 MySQL（MySQL 先于 MariaDB 遍历命中）', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.probeSyntaxFingerprint(syntaxCtx('MySQL'), BASELINE);
  assert.equal(res, 'MySQL');
});

test('语法探针：所有探针均偏离基线 → 返回 null', async () => {
  const fp = new DBFingerprinter();
  // 用空 token 的 mock：所有探针都返回 500 错误页 → 全被排除
  const ctx = {
    httpClient: {
      async request() {
        return { status: 500, data: 'SQL syntax error near near near near near near near' };
      },
    },
    target: createTarget({ url: 'http://mock/?q=1' }),
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null },
    config: {},
  };
  const res = await fp.probeSyntaxFingerprint(ctx, BASELINE);
  assert.equal(res, null);
});

test('语法探针：状态码相同但长度骤变（200 错误页）→ 被 lenOk 守卫排除，返回 null', async () => {
  const fp = new DBFingerprinter();
  const ctx = {
    httpClient: {
      async request(opts) {
        const q = extractInjected(opts);
        // 即便"能解析"（命中 token）也返回一个 200 但巨长的错误页，长度远超 ±容差带
        if (q.includes('sqlite_version')) {
          return { status: 200, data: 'x'.repeat(5000) }; // 长度 5000 vs 基线 6 → 比值≈833 → 排除
        }
        return { status: 500, data: 'SQL error' };
      },
    },
    target: createTarget({ url: 'http://mock/?q=1' }),
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null },
    config: {},
  };
  const res = await fp.probeSyntaxFingerprint(ctx, BASELINE);
  assert.equal(res, null);
});

// ===== 集成：完整 fingerprint() 在无 UNION 回显列时回落到语法探针 =====

// 模拟目标：ORDER BY 全正常（列数枚举收敛到 maxCols）→ UNION 标记无回显（echoCols 空）
// → 进入语法探针；仅 targetDbms 的探针返回良性基线，其余返回错误。
function makeFpNoEchoMock(targetDbms) {
  const tok = TOKEN[targetDbms];
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { status: 200, data: 'normal' }; // 列数枚举正常
      if (/SQLISCANNER/.test(q)) return { status: 200, data: 'no echo column here' }; // 无回显
      // 命中目标库专属 token → 良性基线（≈基线）
      if (tok && q.includes(tok)) return { status: 200, data: 'normal' };
      // 含任一语法探针 token 但非目标库 → 语法错误（状态码/长度偏离基线 → 被排除）
      const anyToken = Object.values(TOKEN).some((t) => q.includes(t));
      if (anyToken) return { status: 500, data: 'SQL syntax error near near near near near near near' };
      // 裸 orig（基线请求）：必须是良性 200 基线，否则 baseline 会被错判成错误页
      return { status: 200, data: 'normal' };
    },
  };
}

test('fingerprint()：无 UNION 回显列 → 落语法探针识别 SQLite', async () => {
  const fp = new DBFingerprinter();
  const target = createTarget({ url: 'http://mock/?q=1' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null };
  const res = await fp.fingerprint({
    httpClient: makeFpNoEchoMock('SQLite'),
    target,
    point,
    config: {},
  });
  assert.equal(res.dbms, 'SQLite');
  assert.ok(res.baseline && typeof res.baseline.status === 'number' && typeof res.baseline.body === 'string');
});

test('fingerprint()：无 UNION 回显列 → 落语法探针识别 PostgreSQL', async () => {
  const fp = new DBFingerprinter();
  const target = createTarget({ url: 'http://mock/?q=1' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null };
  const res = await fp.fingerprint({
    httpClient: makeFpNoEchoMock('PostgreSQL'),
    target,
    point,
    config: {},
  });
  assert.equal(res.dbms, 'PostgreSQL');
});

// [P2-2] 版本分支集成测试：resolveSysQueries / selectPayloads 版本过滤
// 用 mock httpClient 捕获注入 SQL，断言版本感知的查询选择：
//   MySQL <5.7 → password 列；5.7+/未知 → authentication_string
//   SQL Server 2017+ → STRING_AGG+OFFSET/FETCH；<2017 → FOR XML PATH+ROW_NUMBER
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { resolveSysQueries } from '../src/engine/extractionMaps.js';
import { selectPayloads, PAYLOAD_REGISTRY } from '../src/engine/payloadRegistry.js';
import { Exploiter } from '../src/engine/Exploiter.js';

// —— resolveSysQueries 纯函数 ——
test('resolveSysQueries: MySQL 未知版本 → authentication_string（5.7+ 主力保守默认）', () => {
  const sq = resolveSysQueries('MySQL', null);
  assert.match(sq.passwords, /authentication_string/);
});

test('resolveSysQueries: MySQL 8.0 → authentication_string；<5.7 → password 列回退', () => {
  assert.match(resolveSysQueries('MySQL', { major: 8, minor: 0 }).passwords, /authentication_string/);
  const legacy = resolveSysQueries('MySQL', { major: 5, minor: 6 });
  assert.match(legacy.passwords, /IFNULL\(password,/);
  assert.ok(!legacy.passwords.includes('authentication_string'));
});

test('resolveSysQueries: SQL Server 2019 → STRING_AGG 现代路径（databases 原样）', () => {
  const sq = resolveSysQueries('SQL Server', { major: 2019 });
  assert.match(sq.databases, /string_agg/);
  assert.ok(!sq.databases.includes('FOR XML'));
});

test('resolveSysQueries: SQL Server 2014 → FOR XML PATH 聚合（data 含 ROW_NUMBER 分页）', () => {
  const sq = resolveSysQueries('SQL Server', { major: 2014 });
  assert.match(sq.databases, /FOR XML PATH\(''\),TYPE/);
  const q = sq.data('db', 'users', ['id', 'name'], 100, 200);
  assert.match(q, /ROW_NUMBER/);
  assert.match(q, /__rn > 200/);
  assert.ok(!q.includes('OFFSET'));
});

test('resolveSysQueries: SQL Server 2008（<2012）→ 同样 ROW_NUMBER 分页且无 CONCAT/OFFSET', () => {
  const sq = resolveSysQueries('SQL Server', { major: 2008 });
  const q = sq.data('db', 'users', ['id'], 10, 0);
  assert.match(q, /ROW_NUMBER/);
  assert.match(q, /ISNULL\(CAST\(\[id\]/);
  assert.ok(!q.includes('OFFSET'));
  assert.ok(!q.includes('CONCAT('));
});

test('resolveSysQueries: 无版本分支的方言原样返回', () => {
  assert.equal(resolveSysQueries('PostgreSQL', { major: 9, minor: 1 }), resolveSysQueries('PostgreSQL', null));
});

// —— Extractor 集成：enumeratePasswords 按版本捕获 SQL ——
function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

function makeCaptureOracle(captured) {
  return {
    async request(opts) {
      captured.push(extractQuery(opts));
      return { data: `prefix __S__value__E__ suffix`, status: 200 };
    },
  };
}

function buildCtx(httpClient, dbms, dbmsVersion) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', echoCols: [1], confirmed: true },
    dbms,
    dbmsVersion,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

test('Extractor.enumeratePasswords: MySQL 5.6 ctx → 发送 password 列查询', async () => {
  const cap = [];
  await ex.enumeratePasswords(buildCtx(makeCaptureOracle(cap), 'MySQL', { major: 5, minor: 6 }));
  const sql = cap.find((v) => v.includes('mysql.user')) || '';
  assert.match(sql, /IFNULL\(password/);
  assert.ok(!sql.includes('authentication_string'));
});

test('Extractor.enumeratePasswords: MySQL 8.0 ctx → 发送 authentication_string 查询', async () => {
  const cap = [];
  await ex.enumeratePasswords(buildCtx(makeCaptureOracle(cap), 'MySQL', { major: 8, minor: 0 }));
  const sql = cap.find((v) => v.includes('mysql.user')) || '';
  assert.match(sql, /authentication_string/);
});

test('Extractor.enumeratePasswords: 无版本 ctx → 默认 authentication_string（回归守卫）', async () => {
  const cap = [];
  await ex.enumeratePasswords(buildCtx(makeCaptureOracle(cap), 'MySQL', undefined));
  const sql = cap.find((v) => v.includes('mysql.user')) || '';
  assert.match(sql, /authentication_string/);
});

// —— Exploiter 模块加载守卫（buildStackPageSql 分支语义由 versionAtLeast 单测覆盖）——
test('Exploiter 模块加载无循环依赖（import versionAtLeast）', () => {
  assert.equal(typeof Exploiter, 'function');
});

// —— selectPayloads 版本过滤（minVersion/maxVersion 声明）——
test('selectPayloads: dbmsVersion 过滤 minVersion/maxVersion', () => {
  assert.ok(selectPayloads({ dbms: 'MySQL' }).length > 0); // 正常路径有 payload
  // 直接向全局注册表注入临时版本敏感条目验证过滤语义（finally 移除，不污染其他用例）
  const probe = {
    id: 'zz-test-version-gated', dbms: ['MySQL'], technique: 'boolean', level: 1, risk: 1,
    clause: ['where'], boundary: [''], template: '1=1', falseTemplate: '1=2', where: 'value',
    minVersion: 5.7,
  };
  PAYLOAD_REGISTRY.push(probe);
  try {
    const modern = selectPayloads({ dbms: 'MySQL', dbmsVersion: { major: 8, minor: 0 } });
    assert.ok(modern.some((p) => p.id === 'zz-test-version-gated'), '8.0 应命中 minVersion=5.7 条目');
    const old = selectPayloads({ dbms: 'MySQL', dbmsVersion: { major: 5, minor: 6 } });
    assert.ok(!old.some((p) => p.id === 'zz-test-version-gated'), '5.6 不应命中 minVersion=5.7 条目');
    const unknown = selectPayloads({ dbms: 'MySQL', dbmsVersion: { major: null } });
    assert.ok(unknown.some((p) => p.id === 'zz-test-version-gated'), '版本未知保守投放');
    assert.ok(selectPayloads({ dbms: 'MySQL' }).includes(probe), '版本缺省不过滤');
  } finally {
    const i = PAYLOAD_REGISTRY.indexOf(probe);
    if (i >= 0) PAYLOAD_REGISTRY.splice(i, 1);
  }
});

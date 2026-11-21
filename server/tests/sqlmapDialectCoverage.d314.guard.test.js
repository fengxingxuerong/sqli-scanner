// ============================================================================
// tests/sqlmapDialectCoverage.d314.guard.test.js —— 方言定库覆盖的双向守卫
// ============================================================================
// 来源：sqlmap master data/xml/errors.xml（2026-11-21 取，repo 非本仓编写）
//   https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml
// 对账依据：docs/外部测试集对账-sqlmap官方tests-2026-11-21.md
//
// 缺口（D314）：sqlmap 报错指纹覆盖 42 个方言/fork，本仓 ERROR_SIG_BY_DBMS 只有 18 条。
// 其中 SAP MaxDB / Vertica / CUBRID / Presto 四方言 **payload 已由 D307 装配**
// （PAYLOADS['SAP MaxDB'] / PAYLOADS.Vertica / PAYLOADS.CUBRID / PAYLOADS.Presto），
// 但 dbmsFromError 认不出它们的报错 ⇒ 自动定库路径永远命中不到那四套 payload，
// 只能靠显式 --dbms 手动指定。这是「半截能力」，本批补齐。
//
// 本文件钉两组判据：
//   ① 四方言的 sqlmap 官方报错原文必须定库到对应方言（且不能被宽泛签名抢先）；
//   ② 方言覆盖登记表双向一致：sqlmap 已知方言 = 已支持集合 ∪ 显式登记的未支持集合。
//      —— 新增方言不登记会红；登记了却又支持了（白名单腐烂）也会红。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dbmsFromError, ERROR_SIG_BY_DBMS, PAYLOADS, PRECISE_DBMS_FIRST } from '../src/engine/payloads.js';
import { SQL_ERROR_SIG } from '../src/core/errorSig.js';

// ── ① 四方言定库（报错原文逐字取自 sqlmap errors.xml 的正则可匹配形态）──
const DIALECT_CORPUS = [
  // SAP MaxDB: SQL[- ]error.*?POS(\d+) / DriverSapDB / -3014.*Invalid end of SQL statement
  { dbms: 'SAP MaxDB', text: 'SQL error -3014 POS(1): Invalid end of SQL statement' },
  { dbms: 'SAP MaxDB', text: 'com.sap.dbtech.jdbc.exceptions.JdbcSQLException' },
  // Vertica: , Sqlstate: (3F|42).{3}, (Routine|Hint|Position): / com.vertica.jdbc
  { dbms: 'Vertica', text: 'ERROR, Sqlstate: 42601, Routine: Parser, Position: 12' },
  { dbms: 'Vertica', text: 'com.vertica.jdbc.VerticaSQLException' },
  // CUBRID: [CAS INFO / cubrid.jdbc.driver
  { dbms: 'CUBRID', text: '[CAS INFO] SQL syntax error near "x"' },
  { dbms: 'CUBRID', text: 'cubrid.jdbc.driver.CUBRIDException' },
  // Presto/Trino: io.trino.(jdbc|spi). / UNION query has different number of fields
  { dbms: 'Presto', text: 'io.trino.spi.PrestoException: line 1:8: mismatched input' },
  { dbms: 'Presto', text: 'UNION query has different number of fields: 3, 5' },
];

for (const { dbms, text } of DIALECT_CORPUS) {
  test(`dbmsFromError: sqlmap 四方言语料 [${dbms}] 可定库`, () => {
    assert.equal(dbmsFromError(text), dbms, `未定到 ${dbms}：${text}`);
  });
}

// 四方言的 payload key 必须真实存在（防「签名加了但 payload 没了」的空对接）
test('四方言 PAYLOADS 装配存在（签名与 payload 不脱节）', () => {
  for (const key of ['SAP MaxDB', 'Vertica', 'CUBRID', 'Presto']) {
    assert.ok(PAYLOADS[key], `PAYLOADS 缺 ${key}`);
    assert.ok(Array.isArray(PAYLOADS[key].error) && PAYLOADS[key].error.length > 0, `${key}.error 为空`);
  }
});

// 检测门：ErrorDetector 先用 SQL_ERROR_SIG 判「这是不是报错页」，判不出就走不到定库。
// 只补定库不补检测门 = 半截链路（D314 实施中实测：定库 8/8 中、检测门仅 3/8）。
test('SQL_ERROR_SIG 检测门：四方言报错必须判为「报错页」', () => {
  for (const { dbms, text } of DIALECT_CORPUS) {
    assert.ok(SQL_ERROR_SIG.test(text), `检测门漏判 [${dbms}]：${text}`);
  }
});

// 防误报：这四方言的新增特征不得把正常页/文档页判成报错页（D118 教训）
test('SQL_ERROR_SIG 检测门：正常页/文档页不得误命中', () => {
  const NORMAL = [
    'Download the Vertica JDBC driver from the official site',
    'This article compares Trino and Presto performance',
    'CUBRID is an open source DBMS',
    '<h2>SQLite3 SQL Injection</h2>',
    'Uncaught SyntaxError: Unexpected token',
  ];
  for (const s of NORMAL) assert.ok(!SQL_ERROR_SIG.test(s), `误判正常页：${s}`);
});

// ── ② 方言覆盖登记表（双向）──
// sqlmap errors.xml 的 dbms value + fork 全集（2026-11-21 快照，42 个）
const SQLMAP_DIALECTS = [
  'Altibase', 'Apache Derby', 'ClickHouse', 'CockroachDB', 'CrateDB', 'Cubrid',
  'DM8', 'Doris', 'Drizzle', 'DuckDB', 'Firebird', 'FrontBase', 'H2', 'HSQLDB',
  'IBM DB2', 'Informix', 'Ingres', 'InterSystems Cache', 'Mckoi', 'MemSQL',
  'Microsoft Access', 'Microsoft SQL Server', 'MimerSQL', 'MonetDB', 'MySQL',
  'OpenGauss', 'Oracle', 'PostgreSQL', 'Presto', 'Raima Database Manager',
  'SAP HANA', 'SAP MaxDB', 'Snowflake', 'Spanner', 'SQLite', 'StarRocks',
  'Sybase', 'TiDB', 'Trino', 'Vertica', 'Virtuoso', 'YugabyteDB',
];

// 本仓 ERROR_SIG_BY_DBMS 里**没有**对应签名的方言，逐个登记理由。
// 增删本表必须同步真实能力：支持了就删（否则白名单腐烂），不支持就加（否则静默缺口）。
const UNSUPPORTED = {
  Altibase: '本机无真库，无真值报错语料可验；sqlmap 仅 1 条正则',
  CockroachDB: 'PG 系 fork；报错含 crdb_internal.* 但本机无真库可验',
  CrateDB: '本机无真库；sqlmap 仅 1 条正则',
  Doris: 'MySQL 系 fork；aliasPatterns 已归一 MySQL，不单列签名',
  Drizzle: 'MySQL 系 fork；aliasPatterns 已归一 MySQL，不单列签名',
  DuckDB: '本机无真库；PG 系报错措辞，需真库取证后再收',
  FrontBase: '本机无真库，无真值报错语料可验',
  Ingres: '本机无真库，无真值报错语料可验',
  'InterSystems Cache': '本机无真库，无真值报错语料可验',
  Mckoi: '本机无真库，无真值报错语料可验',
  MemSQL: 'MySQL 系 fork；aliasPatterns 已归一 MySQL，不单列签名',
  MimerSQL: '本机无真库，无真值报错语料可验',
  OpenGauss: 'PG 系 fork；aliasPatterns 已归一 PostgreSQL，不单列签名',
  'Raima Database Manager': '本机无真库，无真值报错语料可验',
  'SAP HANA': '本机无真库，无真值报错语料可验',
  Snowflake: '本机无真库；报错无已收锚点（SQL compilation error）',
  Spanner: '本机无真库，无真值报错语料可验',
  StarRocks: 'MySQL 系 fork；aliasPatterns 已归一 MySQL，不单列签名',
  Trino: 'Presto 的改名分支；已由 Presto 签名（io.trino.*）覆盖',
  Virtuoso: '本机无真库，无真值报错语料可验',
  YugabyteDB: 'PG 系 fork；报错含 org.yugabyte.* 但本机无真库可验',
};

// 别名归一：本仓不同名但语义等价的登记名
const SAME_AS = {
  'Microsoft SQL Server': 'SQL Server',
  'IBM DB2': 'DB2',
  'Apache Derby': 'Derby',
  'Microsoft Access': 'Access',
  Cubrid: 'CUBRID',
  'SAP MaxDB': 'SAP MaxDB',
};

// 已支持 = 宽泛顺序表 ∪ 精确优先表（两处都是真订阅源，判据必须都看）
const ours = new Set([
  ...ERROR_SIG_BY_DBMS.map((x) => x.dbms),
  ...PRECISE_DBMS_FIRST.map((x) => x.dbms),
]);

test('方言覆盖双向一致：sqlmap 已知方言 = 已支持 ∪ 已登记未支持', () => {
  const covered = [];
  const missing = [];
  for (const d of SQLMAP_DIALECTS) {
    const key = SAME_AS[d] || d;
    if (ours.has(key) || UNSUPPORTED[d]) covered.push(d);
    else missing.push(d);
  }
  assert.deepEqual(missing, [], `以下方言既无签名也未登记理由（静默缺口）：${missing.join(', ')}`);
  assert.equal(covered.length, SQLMAP_DIALECTS.length);
});

test('未支持白名单无腐烂：登记了却已支持 ⇒ 必须从白名单删除', () => {
  const rotten = Object.keys(UNSUPPORTED).filter((d) => ours.has(SAME_AS[d] || d));
  assert.deepEqual(rotten, [], `以下方言已支持但仍留在 UNSUPPORTED，请删除：${rotten.join(', ')}`);
});

test('未支持白名单每条都有非空理由（不做无理由豁免）', () => {
  for (const [d, why] of Object.entries(UNSUPPORTED)) {
    assert.ok(typeof why === 'string' && why.trim().length >= 6, `${d} 的登记理由过短/为空`);
  }
});

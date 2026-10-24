// ============================================================================
// tests/errorSig.specificity.test.js —— ERROR_SIG 裸词收紧（2026-10-01）回归
// ============================================================================
// 缺陷：ERROR_SIG 原含裸「syntax error」与裸「SQLSTATE」——任意通用 5xx 页
// （JS 框架报错页、文档页、含该词的正文）即可被判定为「数据库报错」，
// prefilter ④ 与二阶触发页判定都会据此放行/定库。
// 修法：换成真实报错形态（PG/MSSQL/SQLite/MySQL-XPATH 四句式 + SQLSTATE[xxxxx]）。
// 本测试钉两侧：真实报错必须仍命中；通用页面短语必须不命中。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ERROR_SIG, dbmsFromError, FINGERPRINT } from '../src/engine/payloads.js';
import { SQL_ERROR_SIG } from '../src/core/scanValidityGuard.js';

// 真实报错原文（各库高频形态）——必须命中
const REAL_ERRORS = [
  `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version`, // MySQL/MariaDB
  `ERROR: syntax error at or near "extractvalue" at character 29`, // PostgreSQL
  `sqlite3.OperationalError: near "x": syntax error`, // SQLite（Python 驱动）
  `near "1"": syntax error`, // SQLite 原生形态
  `XPATH syntax error: '~8.0.33'`, // MySQL extractvalue 回显
  `Microsoft SQL Server: Unclosed quotation mark after the character string`, // MSSQL
  `Incorrect syntax near '\''.`, // MSSQL 裸形态（无厂商名）
  `SQLSTATE[42000]: Syntax error or access violation: 1064`, // PDO 形态
  `ORA-00933: SQL command not properly ended`, // Oracle
  `SQL0104N DB2 SQL Error`, // DB2
  // [D118 2026-10-20] SQLite 强特征：收紧裸 `SQLite3` 后必须保持这些真报错形态命中
  `no such table: users`, // SQLite 原生（此前**不在**通用 SIG，收紧后补入）
  `no such column: foo`, // SQLite 原生
  `SQL logic error near "x"`, // SQLite 原生
  `SQLite3::SQLException: near "x": syntax error`, // SQLite C++ 驱动
  `SQLite3 error: unable to open database file`, // SQLite 带错误词
];

// 通用页面短语（非数据库报错）——必须不命中
const GENERIC_PAGES = [
  `Uncaught SyntaxError: Unexpected token '<'`, // JS 框架报错页
  `The configuration file has a syntax error on line 12`, // 通用配置报错文案
  `See the SQLSTATE reference documentation for details`, // 文档页
  `SQLSTATE handling in PDO`, // 教程正文
  `This page explains common syntax error messages`, // 文档页
  // [D118 2026-10-20] 裸 `SQLite3` 的真实误报源：DVWA/docs 默认页的一节标题。
  // 爬虫扫全站（`--crawl`）时它把 instructions.php 的 doc 参数报成 3 条 High/CVSS 8.2
  // 假漏洞 —— 收紧为「SQLite3 后须跟 `:` / `.` 或 error/exception」后必须不命中。
  `<h2>SQLite3 SQL Injection</h2>`, // DVWA docs 页（误报源，逐字来自实测）
  `<p>Support for SQLite3 is limited, before raising an issue</p>`,
];

test('ERROR_SIG：真实库报错原文全部命中（收紧不得漏真）', () => {
  for (const s of REAL_ERRORS) assert.ok(ERROR_SIG.test(s), `漏命中真实报错：${s}`);
});

test('ERROR_SIG：通用页面短语一律不命中（裸词收紧的防伪）', () => {
  for (const s of GENERIC_PAGES) assert.ok(!ERROR_SIG.test(s), `误命中通用短语：${s}`);
});

test('SQL_ERROR_SIG（scanValidityGuard）同步收紧：SQLSTATE 须带码', () => {
  assert.ok(SQL_ERROR_SIG.test('SQLSTATE[42000]: Syntax error'), '带码形态应命中');
  assert.ok(!SQL_ERROR_SIG.test('SQLSTATE reference documentation'), '裸词不应命中');
});

// [P1-B 2026-10-03] 漂移守卫：ERROR_SIG（payloads）与 SQL_ERROR_SIG（scanValidityGuard）
// 是「响应体在说这是数据库报错」这**同一个语义需求**的两份实现。历史上 ERROR_SIG 于
// 2026-10-01 收紧了真实报错形态，SQL_ERROR_SIG 没跟 ⇒ error-based(extractvalue) 打有洞目标
// 的 500 不被判 selfInflicted，被误判 target_error。本测试把两侧钉在同一语料上：
// 真实报错两侧都要命中，通用页面两侧都不许命中 —— 再出现单向收紧，这里立刻红。
//
// [2026-10-12 单源化升级] 语料守卫暴露过它的盲区：它只钉"固定语料上行为一致"，
// **不校验集合相等** ⇒ 2026-10-03 之后两侧仍持续分叉（PG::/unrecognized token 仅 guard 侧、
// unterminated quoted string/HSQLDB·Derby·Informix exception 形态仅 engine 侧），
// 分叉项不在语料里 ⇒ 零覆盖。现两侧已收敛为 core/errorSig.js 的同一正则对象，
// 本测试加判据①：**两侧必须是同一个对象**（谁把字面量抄回任何一侧，立刻红）。
// 判据②（断言敏感性自检）：证明①不是空转 —— 拿一个"抄了一遍但改坏一项"的副本，
// 同一判据必须能抓住它与真源不同。
test('漂移守卫：两侧同一正则对象 + 语料行为一致（ERROR_SIG ⇄ SQL_ERROR_SIG）', () => {
  // ① 单源身份：集合层面不可能再分叉（对象级判据，比 source 串比对更严）
  assert.equal(ERROR_SIG, SQL_ERROR_SIG,
    'ERROR_SIG 与 SQL_ERROR_SIG 必须是 core/errorSig.js 的同一正则对象（单源）；' +
    '返回两份字面量说明有人把实现抄回了本地 —— 请改 core/errorSig.js 一处。');
  assert.equal(ERROR_SIG.source, SQL_ERROR_SIG.source, '两侧 source 不一致（单源被破坏）');
  assert.equal(ERROR_SIG.flags, SQL_ERROR_SIG.flags, '两侧 flags 不一致（单源被破坏）');

  // ② 断言敏感性自检：判据①对"分叉副本"必须敏感（否则可能是碰巧通过的空转断言）
  const divergentCopy = new RegExp(ERROR_SIG.source.replace('unrecognized token', 'ZZZ_not_a_real_sig'), ERROR_SIG.flags);
  assert.notEqual(divergentCopy.source, SQL_ERROR_SIG.source,
    '敏感性自检失败：判据①对分叉副本不敏感 ⇒ 断言可能空转');

  // ③ 语料行为（原守卫保留）：真实报错两侧都要命中，通用页面两侧都不许命中
  for (const s of REAL_ERRORS) {
    assert.ok(ERROR_SIG.test(s), `ERROR_SIG 自身漏命中：${s}`);
    assert.ok(SQL_ERROR_SIG.test(s), `SQL_ERROR_SIG 与 ERROR_SIG 分叉（漏命中）：${s}`);
  }
  for (const s of GENERIC_PAGES) {
    assert.ok(!ERROR_SIG.test(s), `ERROR_SIG 误命中通用短语：${s}`);
    assert.ok(!SQL_ERROR_SIG.test(s), `SQL_ERROR_SIG 误命中通用短语：${s}`);
  }
});

// [2026-10-12] 单源化的回归锚点：历史分叉项（仅一侧有的形态）现在两侧都必须认。
// 这条同时是"并集决策"的钉子 —— 将来若要从并集里删某项，必须来这里改断言，
// 逼使删除动作有一次显式评审（而不是悄悄少一项）。
test('单源并集锚点：历史分叉形态两侧均命中（PG:: / unrecognized token / HSQLDB exception 族）', () => {
  for (const s of [
    'ERROR: invalid input syntax for type integer: "abc" (PG::SyntaxError)', // PG::（仅 guard 侧有过）
    'sqlite3.OperationalError: unrecognized token: "\\"1\\""', // unrecognized token（仅 guard 侧有过）
    'org.hsqldb.HsqlException: HSQLDB exception: user lacks privilege or object not found', // HSQLDB exception 族
    'Apache Derby: Derby SQLException: Syntax error', // Derby exception 族（engine 侧独有过）
    'unterminated quoted string at or near "\'x"', // unterminated quoted string（engine 侧独有过）
  ]) {
    assert.ok(ERROR_SIG.test(s), `单源后仍应命中：${s}`);
    assert.ok(SQL_ERROR_SIG.test(s), `单源后仍应命中：${s}`);
  }
});

test('dbmsFromError：PDO SQLSTATE 形态仍能定库', () => {
  assert.equal(dbmsFromError('SQLSTATE[42000]: [Microsoft][ODBC] SQL Server'), 'SQL Server');
});

// ===== [D157 2026-10-25] 三 Java 引擎的「报错定库」：原文里没有库名 =====
// 缺陷实测（e2e/multi-engine-lab 真 JDBC 内存库，NO_WAF=1）：Derby 三个场景检出正常、
// 但 `定库=null（未识别）` —— 报错原文 `Syntax error: Encountered "\'" at line 1, column 31.`
// 里没有 "Derby"，原签名只认品牌词/驱动类名 ⇒ 定库 null ⇒ 注释符与提取语句按默认选。
// H2 / HSQLDB 同样形态（它们只是靠 UNION 版本回显才定出来的，盲注档也为 null）。
const REAL_DERBY_ERR = `Syntax error: Encountered "\\'" at line 1, column 31.`;
const REAL_HSQLDB_ERR = `unexpected token: ' in statement [SELECT * FROM USERS WHERE NAME=alice']`;
const REAL_H2_ERR = `Syntax error in SQL statement "SELECT * FROM USERS WHERE ID=1'"; expected "identifier"`;

test('[D157] 三引擎真实报错原文都能定库（不靠品牌词）', () => {
  assert.equal(dbmsFromError(REAL_DERBY_ERR), 'Derby', 'Derby 的 Encountered/at line N, column M 句式');
  assert.equal(dbmsFromError('ERROR 42X01: Syntax error: Encountered "AND" at line 1, column 20.'), 'Derby',
    'Derby SQLState 42Xxx 前缀');
  assert.equal(dbmsFromError(REAL_HSQLDB_ERR), 'HSQLDB', 'HSQLDB 的 unexpected token ... in statement [ 句式');
  assert.equal(dbmsFromError(REAL_H2_ERR), 'H2', 'H2 的 Syntax error in SQL statement 句式');
});

test('[D157] 反向：JS 报错页不得被认成 HSQLDB（裸 unexpected token 是陷阱）', () => {
  for (const s of [
    `Uncaught SyntaxError: Unexpected token '<'`,
    `Uncaught SyntaxError: Unexpected token '<' (at app.js:1:1)`,
  ]) {
    assert.notEqual(dbmsFromError(s), 'HSQLDB', `JS 报错不得定库 HSQLDB：${s}`);
  }
});

test('[D157] Derby 响应头签名不再认裸 java（Server: Java/1.x 是误报源）', () => {
  const sigs = FINGERPRINT.Derby || [];
  const matches = (s) => sigs.some((sig) => sig.match.test(s));
  assert.ok(matches('Apache Derby Network Server - 10.16.1.1'), 'Derby 品牌词仍应命中');
  assert.ok(!matches('Java/1.8.0_301'), '裸 Java 服务不得判成 Derby（会按错方言投 payload）');
});

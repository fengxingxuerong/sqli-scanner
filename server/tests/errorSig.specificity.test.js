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
import { ERROR_SIG, dbmsFromError } from '../src/engine/payloads.js';
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
];

// 通用页面短语（非数据库报错）——必须不命中
const GENERIC_PAGES = [
  `Uncaught SyntaxError: Unexpected token '<'`, // JS 框架报错页
  `The configuration file has a syntax error on line 12`, // 通用配置报错文案
  `See the SQLSTATE reference documentation for details`, // 文档页
  `SQLSTATE handling in PDO`, // 教程正文
  `This page explains common syntax error messages`, // 文档页
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
test('漂移守卫：真实报错两侧一致命中、通用页两侧一致不命中（ERROR_SIG ⇄ SQL_ERROR_SIG）', () => {
  for (const s of REAL_ERRORS) {
    assert.ok(ERROR_SIG.test(s), `ERROR_SIG 自身漏命中：${s}`);
    assert.ok(SQL_ERROR_SIG.test(s), `SQL_ERROR_SIG 与 ERROR_SIG 分叉（漏命中）：${s}`);
  }
  for (const s of GENERIC_PAGES) {
    assert.ok(!ERROR_SIG.test(s), `ERROR_SIG 误命中通用短语：${s}`);
    assert.ok(!SQL_ERROR_SIG.test(s), `SQL_ERROR_SIG 误命中通用短语：${s}`);
  }
});

test('dbmsFromError：PDO SQLSTATE 形态仍能定库', () => {
  assert.equal(dbmsFromError('SQLSTATE[42000]: [Microsoft][ODBC] SQL Server'), 'SQL Server');
});

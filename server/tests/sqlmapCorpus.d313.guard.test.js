// ============================================================================
// tests/sqlmapCorpus.d313.guard.test.js —— 用 sqlmap 官方报错语料反推定库的回归守卫
// ============================================================================
// 来源：sqlmap master data/xml/errors.xml（2026-11-21 取，repo 非本仓编写）
//   https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml
// 对账脚本：.box-agent-scratch/sqlmap-tests/reconcile2.mjs（判据2 真实报错原文样本）
//
// 缺陷（D313）：ERROR_SIG_BY_DBMS 是「命中即停」的顺序表；宽泛签名 Sybase 的
// `SQL error code` 与 SQL Server 的 `ODBC` 排在更具体的 Firebird / Informix 之前，
// 导致 sqlmap 官方语料里这两库的真实报错被误判成别的库 ⇒ DBFingerprinter /
// ErrorDetector 定库错 ⇒ 注释符与 payload 族错配 ⇒ 漏检。
// 修法：把 Firebird / Informix 的强特征签名前移到宽泛签名之前（不动宽泛词，
// 保住 `SQLSTATE[42000]: [Microsoft][ODBC] SQL Server` → SQL Server 的既有语义）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dbmsFromError } from '../src/engine/payloads/index.js';

// sqlmap errors.xml 逐字报错形态（非臆造）：
//   Firebird:  Dynamic SQL Error.{1,10}SQL error code
//   Informix:  ODBC Informix driver / Informix ODBC Driver
const CORPUS = [
  { dbms: 'Firebird', text: 'Dynamic SQL Error SQL error code = -104' },
  { dbms: 'Informix', text: 'ODBC Informix driver error' },
  { dbms: 'Informix', text: 'Informix ODBC Driver SQL error' },
];

for (const { dbms, text } of CORPUS) {
  test(`dbmsFromError: sqlmap 语料 [${dbms}] 不被宽泛签名抢先`, () => {
    assert.equal(dbmsFromError(text), dbms, `误判：${text}`);
  });
}

// 防回归：宽泛词原有的正确语义不能因为前移而被破坏
test('dbmsFromError: ODBC 的 SQL Server 既有语义保持', () => {
  assert.equal(dbmsFromError('SQLSTATE[42000]: [Microsoft][ODBC] SQL Server'), 'SQL Server');
});

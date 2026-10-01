// =====================================================================
// identityQueries.js — 主机名 / is-dba / schema / 权限 / 角色枚举模板
// 自 extractionMaps.js 拆出（纯搬移）。
// =====================================================================
import { escSql } from '../DialectSqlBuilder.js';

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
// 返回列定义元数据（列名、类型、可空、默认值），行分隔符 0x1E/CHAR(30)，列分隔符 CHAR(31)。
export const SCHEMA_QUERY = {
  /** @type {(db: string, table: string) => string} */
  MySQL: (db, table) =>
    // [P2 审计修复 2026-09-20] 原写 `SEPARATOR CHAR(30)` —— **MySQL 语法错（1064）**：
    // MySQL 的 GROUP_CONCAT 分隔符语法节点是 `SEPARATOR_SYM text_string`，**只接受字面量**，
    // 不接受表达式（MySQL Bug #64600，官方答复「works as designed」；sql_yacc.yy 亦为
    // `SEPARATOR_SYM text_string`）。实测同库的 SYS_QUERIES.MySQL.data 早已因同一原因
    // 改用 hex 字面量 0x1E（见本文件 line 33 注释）。→ `enumerateSchema` 在
    // MySQL/MariaDB/TiDB 上**恒失败返回 null**。此处同样改用 0x1E 字面量。
    // 注：多 expr 形态 GROUP_CONCAT(a,CHAR(31),b,...) 是合法的——多个 expr 之间用
    // （默认或指定的）分隔符连接，故选保留该形态表达「列定义用 CHAR(31) 分隔」的语义。
    `SELECT GROUP_CONCAT(COLUMN_NAME,CHAR(31),COLUMN_TYPE,CHAR(31),IS_NULLABLE,CHAR(31),IFNULL(COLUMN_DEFAULT,'NULL') SEPARATOR 0x1E) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='${escSql(db)}' AND TABLE_NAME='${escSql(table)}'`,
  /** @type {(db: string, table: string) => string} */
  PostgreSQL: (db, table) =>
    `SELECT string_agg(column_name||' '||data_type||CASE WHEN character_maximum_length IS NOT NULL THEN '('||character_maximum_length||')' ELSE '' END, CHR(30)) FROM information_schema.columns WHERE table_name='${escSql(table)}' AND table_schema='public'`,
  'SQL Server': (db, table) =>
    `SELECT string_agg(CONCAT(COLUMN_NAME,CHAR(31),DATA_TYPE,CHAR(31),IS_NULLABLE,CHAR(31),ISNULL(COLUMN_DEFAULT,'NULL')), CHAR(30)) FROM information_schema.columns WHERE table_name='${escSql(table)}' AND TABLE_SCHEMA='dbo'`,
  /** @type {(table: string) => string} */
  SQLite: (table) =>
    `SELECT group_concat(name||' '||type) FROM pragma_table_info('${escSql(table)}')`,
  /** @type {(db: string, table: string) => string} */
  Oracle: (db, table) =>
    `SELECT listagg(column_name||' '||data_type, CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name='${escSql(table)}'`,
  /** @type {(db: string, table: string) => string} */
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


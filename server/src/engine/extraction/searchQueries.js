// =====================================================================
// searchQueries.js — 跨库搜索列/表与带 WHERE 行数统计模板（--search / --count --where）
// 自 extractionMaps.js 拆出（纯搬移）。
// =====================================================================
import { escSql, escBacktick, escDq, escBracket } from '../DialectSqlBuilder.js';

// ============================================================================
// [sqlmap 对标 --search] 跨库搜索列名/表名查询模板
// 返回 "db.table.column" 或 "db.table" 逗号分隔串，由 Extractor.searchColumns /
// searchTables 拆分后返回。searchTerm 单引号已转义（escSql），支持 LIKE 模式匹配。
// MySQL/PG/MSSQL 用 information_schema，Oracle 用 all_tab_columns/all_tables，
// SQLite 用 sqlite_master（表搜索）+ 逐表 pragma_table_info（列搜索，返回 null 由调用方迭代）。
// ============================================================================
export const SEARCH_COLUMNS_QUERY = {
  /** @type {(searchTerm: string) => string} */
  MySQL: (searchTerm) =>
    `SELECT GROUP_CONCAT(CONCAT(table_schema, '.', table_name, '.', column_name) SEPARATOR ',') FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  PostgreSQL: (searchTerm) =>
    `SELECT string_agg(table_schema || '.' || table_name || '.' || column_name, ',') FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  'SQL Server': (searchTerm) =>
    `SELECT string_agg(TABLE_SCHEMA + '.' + TABLE_NAME + '.' + COLUMN_NAME, ',') FROM information_schema.columns WHERE COLUMN_NAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Oracle: (searchTerm) =>
    `SELECT listagg(owner || '.' || table_name || '.' || column_name, ',') WITHIN GROUP (ORDER BY owner, table_name, column_name) FROM all_tab_columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  // SQLite 无 information_schema，pragma_table_info 需逐表查询 -> null，由 searchColumns 迭代处理
  SQLite: null,
  /** @type {(searchTerm: string) => string} */
  ClickHouse: (searchTerm) =>
    `SELECT groupArray(concat(database, '.', table, '.', name)) FROM system.columns WHERE name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  DB2: (searchTerm) =>
    `SELECT listagg(TABSCHEMA || '.' || TABNAME || '.' || COLNAME, ',') FROM SYSCAT.COLUMNS WHERE COLNAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Sybase: (searchTerm) =>
    `SELECT list(db_name() || '.' || so.name || '.' || sc.name) FROM syscolumns sc, sysobjects so WHERE sc.id=so.id AND sc.name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Firebird: (searchTerm) =>
    `SELECT list(rdb$relation_name || '.' || rdb$field_name) FROM rdb$relation_fields WHERE rdb$field_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  H2: (searchTerm) =>
    `SELECT GROUP_CONCAT(table_schema || '.' || table_name || '.' || column_name) FROM information_schema.columns WHERE column_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  HSQLDB: (searchTerm) =>
    `SELECT GROUP_CONCAT(TABLE_SCHEMA || '.' || TABLE_NAME || '.' || COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  MonetDB: (searchTerm) =>
    `SELECT group_concat(s.name || '.' || t.name || '.' || c.name) FROM sys.columns c, sys.tables t, sys.schemas s WHERE c.table_id=t.id AND t.schema_id=s.id AND c.name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
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
  /** @type {(searchTerm: string) => string} */
  MySQL: (searchTerm) =>
    `SELECT GROUP_CONCAT(CONCAT(table_schema, '.', table_name) SEPARATOR ',') FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  PostgreSQL: (searchTerm) =>
    `SELECT string_agg(table_schema || '.' || table_name, ',') FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  'SQL Server': (searchTerm) =>
    `SELECT string_agg(TABLE_SCHEMA + '.' + TABLE_NAME, ',') FROM information_schema.tables WHERE TABLE_NAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Oracle: (searchTerm) =>
    `SELECT listagg(owner || '.' || table_name, ',') WITHIN GROUP (ORDER BY owner, table_name) FROM all_tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  SQLite: (searchTerm) =>
    `SELECT group_concat(name) FROM sqlite_master WHERE type='table' AND name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  ClickHouse: (searchTerm) =>
    `SELECT groupArray(concat(database, '.', name)) FROM system.tables WHERE name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  DB2: (searchTerm) =>
    `SELECT listagg(TABSCHEMA || '.' || TABNAME, ',') FROM SYSCAT.TABLES WHERE TABNAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Sybase: (searchTerm) =>
    `SELECT list(db_name() || '.' || name) FROM sysobjects WHERE type='U' AND name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  Firebird: (searchTerm) =>
    `SELECT list(rdb$relation_name) FROM rdb$relations WHERE rdb$system_flag=0 AND rdb$relation_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  H2: (searchTerm) =>
    `SELECT GROUP_CONCAT(table_schema || '.' || table_name) FROM information_schema.tables WHERE table_name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  HSQLDB: (searchTerm) =>
    `SELECT GROUP_CONCAT(TABLE_SCHEMA || '.' || TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
  MonetDB: (searchTerm) =>
    `SELECT group_concat(s.name || '.' || t.name) FROM sys.tables t, sys.schemas s WHERE t.schema_id=s.id AND t.name LIKE '%${escSql(searchTerm)}%'`,
  /** @type {(searchTerm: string) => string} */
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
  /** @type {(db: string, table: string, where: string|null) => string} */
  MySQL: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\` WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  PostgreSQL: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  'SQL Server': (db, table, where) =>
    `SELECT COUNT(*) FROM [${escBracket(table)}] WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  Oracle: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  SQLite: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  ClickHouse: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\` WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  DB2: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  Sybase: (db, table, where) =>
    `SELECT COUNT(*) FROM [${escBracket(table)}] WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  Firebird: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  H2: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  HSQLDB: (db, table, where) =>
    `SELECT COUNT(*) FROM \`${escBacktick(table)}\` WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  MonetDB: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  /** @type {(db: string, table: string, where: string|null) => string} */
  Informix: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
  Access: null,
  /** @type {(db: string, table: string, where: string|null) => string} */
  Derby: (db, table, where) =>
    `SELECT COUNT(*) FROM "${escDq(table)}" WHERE ${where}`,
};
COUNT_WHERE_QUERY.MariaDB = COUNT_WHERE_QUERY.MySQL;
COUNT_WHERE_QUERY.TiDB = COUNT_WHERE_QUERY.MySQL;
COUNT_WHERE_QUERY.DM8 = COUNT_WHERE_QUERY.Oracle;


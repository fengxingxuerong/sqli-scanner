// =====================================================================
// extractionMaps.js — 各方言查询/函数映射表的统一出口（facade）
// [拆分 2026-10-01] 17 张表按职责分片到 ./extraction/*（纯搬移，零行为变化），
// 本文件只做 re-export：Extractor / blindExtractor / 各测试的既有导入路径不变。
// 分片：sysQueries（枚举/拖库模板+别名）· blindFns（LEN/SUB/ASCII 二分函数）
//   · scalarExprs（版本/延时/当前库/当前用户）· identityQueries（hostname/is-dba/
//   schema/privileges/roles）· searchQueries（--search/--count-where）
//   · sysQueriesVersioned（resolveSysQueries 版本分支 + MSSQL <2017 降级）
// =====================================================================
export { SYS_QUERIES } from './extraction/sysQueries.js';
export { LEN_FN, SUB_FN, ASCII_FN } from './extraction/blindFns.js';
export { VERSION_EXPR, TIME_COND, CURRENT_DB_EXPR, CURRENT_USER_EXPR } from './extraction/scalarExprs.js';
export { HOSTNAME_QUERY, ISDBA_QUERY, SCHEMA_QUERY, PRIVILEGES_QUERY, ROLES_QUERY } from './extraction/identityQueries.js';
export { SEARCH_COLUMNS_QUERY, SEARCH_TABLES_QUERY, COUNT_WHERE_QUERY } from './extraction/searchQueries.js';
export { resolveSysQueries } from './extraction/sysQueriesVersioned.js';

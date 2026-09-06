// ============================================================================
// DialectSqlBuilder.js —— 方言 SQL 知识收敛中心（单一事实源）
//
// 统一管理 18 种 DBMS 的 SQL 方言差异，消除原散落在 6 个文件中的重复代码：
//   resolveDbms   — 原 4 份拷贝（Extractor/Exploiter/injection/InlineQueryDetector）
//   fromDummy     — 原 2 份拷贝（DBFingerprinter/injection）
//   转义函数       — 原 2 份（Extractor 定义 + ColumnTypeEnumerator 内联 e 函数）
//   escCols       — 原 1 份（Extractor），被 SYS_QUERIES/Extractor 使用
//   tableRef      — 原 1 份（Extractor），被 dumpData 使用
//   quoteCol      — 原 1 份（Exploiter），被 buildStackPageSql 使用
//   WRAP          — 原 1 份（DBFingerprinter），被 Extractor re-export
//   INLINE_CONCAT — 原 1 份（InlineQueryDetector），被内联检测使用
//   HIGH_FREQ_DBMS — 原 1 份（DBFingerprinter），被指纹识别使用
//
// 本模块不导入任何 engine 子模块（纯数据 + 纯函数），无循环依赖风险。
// 各调用方改为从此模块导入，消除重复拷贝导致的判据漂移。
// ============================================================================

// ── 标识符/字符串转义 ──────────────────────────────────────────────────────
// 库名/表名/列名来自目标数据库自身内容（information_schema / sqlite_master 等），
// 恶意或异常命名（含单引号/反引号/双引号/] 等）会破坏提取 SQL，甚至被当作二次注入
// 改写查询语义。各方言转义规则：
//   MySQL 反引号内 `` 转义、单引号串内 '' 转义；
//   PostgreSQL/Oracle 双引号标识符内 "" 转义；SQL Server [] 内 ]] 转义。
export const escSql = (s) => String(s).replace(/'/g, "''");
export const escBacktick = (s) => String(s).replace(/`/g, '``');
export const escDq = (s) => String(s).replace(/"/g, '""');
export const escBracket = (s) => String(s).replace(/\]/g, ']]');

// ── DBMS 归一化 ────────────────────────────────────────────────────────────
// MariaDB/TiDB 与 MySQL 协议互通，DM8 与 Oracle 兼容：
// 指纹层已独立区分，但提取/枚举/利用复用对应分支。
// [审计 P2] 原实现各文件用 === 精确匹配或各自 regex，导致传入 'mariadb'（小写）
// 时某些模块不归一化 → 两模块 DBMS 不一致。统一为 regex 匹配。
// [对标扩展] 边缘库方言别名归一化到母库（低成本扩支持面，复用母库 payload/指纹/提取映射）：
//   · MySQL 系：OceanBase（OB MySQL 模式）/ Cubrid（兼容 MySQL 协议）/ GBase 8a / SAP MaxDB
//   · PostgreSQL 系：CockroachDB（兼容 PG）/ KingbaseES 人大金仓 / Vertica（近似 PG 语法）
// 这些库在 FINGERPRINT 无独立签名时识别不到，但归一化后检测/提取链路自动获得母库能力，
// 避免「识别为未知库 → 死回退」的语义损失。DBMS_LIST 保持 18 个标准名不变。
export function resolveDbms(dbms) {
  if (!dbms) return null;
  if (/mariadb|tidb|oceanbase|cubrid|\bgbase\b|maxdb|sap\s*db/i.test(dbms)) return 'MySQL';
  if (/dm8|dameng/i.test(dbms)) return 'Oracle';
  if (/cockroachdb|kingbase|kingbasees|vertica/i.test(dbms)) return 'PostgreSQL';
  return dbms; // MySQL / PostgreSQL / SQLite / SQL Server / Oracle / ClickHouse
}

// [⑳] 驱动方言名（小写）→ DBMS_LIST 中的标准名称
// DirectConnector.getDialect() 返回的 driver.dialect 是小写短名，
// 需映射为 DBMS_LIST 中的标准名称后才能被 Extractor/Exploiter 等消费方使用。
const DIALECT_TO_DBMS = {
  mysql: 'MySQL', mariadb: 'MariaDB', tidb: 'TiDB',
  postgres: 'PostgreSQL', postgresql: 'PostgreSQL',
  sqlite: 'SQLite',
  sqlserver: 'SQL Server', mssql: 'SQL Server',
  oracle: 'Oracle', dm8: 'DM8', dameng: 'DM8',
  clickhouse: 'ClickHouse', db2: 'DB2', sybase: 'Sybase',
  firebird: 'Firebird', informix: 'Informix',
  h2: 'H2', access: 'Access', hsqldb: 'HSQLDB',
  derby: 'Derby', monetdb: 'MonetDB',
  // [对标扩展] 边缘库方言 → 母库（与 resolveDbms 归一化一致）
  oceanbase: 'MySQL', cubrid: 'MySQL', gbase: 'MySQL', maxdb: 'MySQL',
  cockroachdb: 'PostgreSQL', cockroach: 'PostgreSQL',
  kingbase: 'PostgreSQL', kingbasees: 'PostgreSQL', vertica: 'PostgreSQL',
};
export function dialectToDbms(dialect) {
  if (!dialect) return null;
  return DIALECT_TO_DBMS[String(dialect).toLowerCase()] || null;
}

// ── 伪表 FROM 子句 ────────────────────────────────────────────────────────
// UNION 探测/标量提取用的伪表（dual 等价物）：各 DBMS 语法不同。
// Oracle/DM8→dual；DB2/Derby→SYSIBM.SYSDUMMY1；Firebird/Informix→各自专属伪表；
// Access→MSysObjects；HSQLDB→VALUES(0) 派生表；MonetDB→sys.version；
// 其余库（含 MySQL/TiDB/PG/SQLite/MSSQL/ClickHouse/H2/Sybase）无 dual 可省略。
export function fromDummy(dbms) {
  switch (dbms) {
    case 'Oracle':
    case 'DM8': return ' FROM dual';
    case 'DB2':
    case 'Derby': return ' FROM SYSIBM.SYSDUMMY1';
    case 'Firebird': return ' FROM RDB$DATABASE';
    case 'Informix': return ' FROM systables WHERE tabid=1';
    case 'Access': return ' FROM MSysObjects';
    case 'HSQLDB': return ' FROM (VALUES(0)) t';
    case 'MonetDB': return ' FROM sys.version';
    default: return ''; // MySQL/TiDB/PG/SQLite/MSSQL/ClickHouse/H2/Sybase 无 dual
  }
}

// [P2-5] --union-from：用户强制指定 UNION 探测/提取的 FROM 子句（sqlmap 语义：
// 已知伪表需求时跳过方言自动判定，如 --union-from=dual 强制 Oracle 风格）。
// 仅当 unionFrom 非空时覆盖 fromDummy 自动结果；否则完全走方言自动判定。
// 注意：值由用户 CLI 提供，此处按原样拼入（CLI 层已做长度截断）；调用方拼接前
// 会先经 sanitizeUnionFrom 清洗（仅允许 [A-Za-z0-9_ .$] 与括号，杜绝注释/分号逃逸）。
export function resolveFromClause(dbms, unionFrom) {
  const uf = sanitizeUnionFrom(unionFrom);
  return uf ? ` FROM ${uf}` : fromDummy(dbms);
}

// 清洗 unionFrom 用户输入：仅保留安全字符集，防注入逃逸（'--'、'/*'、';' 等一律剔除）
export function sanitizeUnionFrom(v) {
  if (v == null) return '';
  const cleaned = String(v).replace(/[^A-Za-z0-9_ .$()]/g, '').trim();
  return cleaned;
}

// ── 标识符引用（列名/表名引号） ────────────────────────────────────────────
// 按方言包裹列名（防不可信数据库返回恶意列名破坏 SQL 语义）
export function escCols(cols, dialect) {
  if (!Array.isArray(cols) || cols.length === 0) return '*';
  const wrap = (c) => {
    const safe = String(c).replace(/[`"\[\]]/g, ''); // 去除标识符边界符
    switch (dialect) {
      case 'MySQL': case 'TiDB': case 'MariaDB': case 'ClickHouse': case 'HSQLDB': case 'MonetDB':
        return '`' + safe + '`';
      case 'PostgreSQL': case 'SQLite': case 'Oracle': case 'DM8': case 'DB2': case 'Derby': case 'Firebird': case 'H2':
        return '"' + safe + '"';
      case 'SQL Server': case 'Access': case 'Sybase':
        return '[' + safe + ']';
      default:
        return safe;
    }
  };
  return cols.map(wrap).join(',');
}

// 表引用构造：MySQL/ClickHouse 带 db 前缀；其余库忽略 db（仅 schema 层语义）。
export function tableRef(edb, db, table) {
  const t = String(table);
  switch (edb) {
    case 'MySQL':
    case 'ClickHouse':
      return `\`${escBacktick(db)}\`.\`${escBacktick(t)}\``;
    case 'SQL Server':
      return `[${escBracket(t)}]`;
    case 'HSQLDB':
      return `\`${escBacktick(t)}\``;
    default:
      return `"${escDq(t)}"`;
  }
}

// 列名引号适配（Exploiter 原有实现，改用统一 resolveDbms）
// MySQL/MariaDB/SQLite 用反引号，其余（PG/SQLServer/Oracle）用双引号
export function quoteCol(c, db) {
  const dq = ['PostgreSQL', 'SQL Server', 'Oracle'].includes(resolveDbms(db));
  return dq ? `"${c}"` : `\`${c}\``;
}

// ── UNION 标记包裹 ─────────────────────────────────────────────────────────
// 不同库对标记包裹的方式（UNION 提取版本时定位回显列）
export const WRAP = {
  MySQL: (s) => `CONCAT('__S__',CAST((${s}) AS CHAR),'__E__')`,
  // [⑯] 补 MariaDB key（与 MySQL 相同，resolveDbms 已归一化但字典应完整）
  MariaDB: (s) => `CONCAT('__S__',CAST((${s}) AS CHAR),'__E__')`,
  PostgreSQL: (s) => `('__S__' || CAST((${s}) AS TEXT) || '__E__')`,
  SQLite: (s) => `('__S__' || (${s}) || '__E__')`,
  'SQL Server': (s) => `('__S__'+CAST((${s}) AS VARCHAR(MAX))+'__E__')`,
  Oracle: (s) => `('__S__' || TO_CHAR((${s})) || '__E__')`,
  // TiDB：MySQL 协议兼容，复用 MySQL WRAP
  TiDB: (s) => `CONCAT('__S__',CAST((${s}) AS CHAR),'__E__')`,
  // DM8：Oracle 兼容，复用 Oracle WRAP
  DM8: (s) => `('__S__' || TO_CHAR((${s})) || '__E__')`,
  // ClickHouse：用 concat 包裹（CH 原生 string 拼接），无需 CAST 到定长类型
  ClickHouse: (s) => `concat('__S__', toString((${s})), '__E__')`,
  // —— C 方向新增（最小适配，方言包裹，待真实环境验证）——
  // DB2/Firebird/Informix/H2 用 || 拼接 + CAST 到 VARCHAR(4000)
  DB2: (s) => `('__S__' || CAST((${s}) AS VARCHAR(4000)) || '__E__')`,
  Firebird: (s) => `('__S__' || CAST((${s}) AS VARCHAR(4000)) || '__E__')`,
  Informix: (s) => `('__S__' || CAST((${s}) AS VARCHAR(4000)) || '__E__')`,
  H2: (s) => `('__S__' || CAST((${s}) AS VARCHAR(4000)) || '__E__')`,
  // Sybase（ASE）：+ 拼接，复用 MSSQL 风格
  Sybase: (s) => `('__S__'+CAST((${s}) AS VARCHAR(MAX))+'__E__')`,
  // —— D 方向新增（方言包裹，待真实环境验证）——
  // Access 用 & 拼接（Access 无 || 与 CAST，类型转换用 CStr）；HSQLDB/Derby/MonetDB 用 || 拼接 + CAST
  Access: (s) => `('__S__' & CStr(${s}) & '__E__')`,
  HSQLDB: (s) => `('__S__' || CAST((${s}) AS VARCHAR(1000)) || '__E__')`,
  Derby: (s) => `('__S__' || CAST((${s}) AS VARCHAR(32672)) || '__E__')`,
  MonetDB: (s) => `('__S__' || CAST((${s}) AS VARCHAR(1024)) || '__E__')`,
};

// ── 高频 DBMS 遍历顺序 ─────────────────────────────────────────────────────
// 无回显/无响应头特征时按「高频库顺序」遍历报错/时间签名定库（命中即停），
// 避免 dbms 恒为 null 导致各检测器死回退 MySQL（P1-D3）。
// [⑯] 补全至全部 18 库：高频库在前（命中率 >95%），低频库在后兜底。
// 命中即停策略使高频场景请求数零增长；仅在响应头/UNION 版本/报错均不命中时
// 才追加低频库探测，避免 DB2/Firebird 等冷门库指纹恒为 null 导致下游死回退 MySQL。

// [P2-5] --no-cast 变体：数据检索时禁用 CAST()/TO_CHAR()/toString() 显式转换
// （对标 sqlmap --no-cast：关闭提取阶段的 CAST 包裹）。各库改用隐式文本化：
//   · CONCAT / || / + / & 拼接在多数库会对操作数做隐式类型转换（MySQL CONCAT 数字→文本；
//     Oracle/PG/DB2 等 || 数字→文本；Access & 数字→文本）
//   · SQL Server/Sybase 例外：'+' 遇 int 直接报错（需 CONVERT），故仍保留显式转换——
//     noCast 对该两库不降级正确性（sqlmap 亦仅在支持隐式转换的库生效）
//   · ClickHouse toString() 省略后 concat 对数字隐式转 String
// WRAP_NOCAST 仅覆盖支持隐式文本化的库；其余库（SQL Server/Sybase）由调用方回退 WRAP 显式版。
export const WRAP_NOCAST = {
  MySQL: (s) => `CONCAT('__S__',(${s}),'__E__')`,
  MariaDB: (s) => `CONCAT('__S__',(${s}),'__E__')`,
  TiDB: (s) => `CONCAT('__S__',(${s}),'__E__')`,
  PostgreSQL: (s) => `('__S__' || (${s}) || '__E__')`,
  SQLite: (s) => `('__S__' || (${s}) || '__E__')`,
  Oracle: (s) => `('__S__' || (${s}) || '__E__')`,
  DM8: (s) => `('__S__' || (${s}) || '__E__')`,
  ClickHouse: (s) => `concat('__S__', (${s}), '__E__')`,
  DB2: (s) => `('__S__' || (${s}) || '__E__')`,
  Firebird: (s) => `('__S__' || (${s}) || '__E__')`,
  Informix: (s) => `('__S__' || (${s}) || '__E__')`,
  H2: (s) => `('__S__' || (${s}) || '__E__')`,
  Access: (s) => `('__S__' & (${s}) & '__E__')`,
  HSQLDB: (s) => `('__S__' || (${s}) || '__E__')`,
  Derby: (s) => `('__S__' || (${s}) || '__E__')`,
  MonetDB: (s) => `('__S__' || (${s}) || '__E__')`,
};

export const HIGH_FREQ_DBMS = [
  'MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite',
  'MariaDB', 'TiDB', 'DM8', 'ClickHouse', 'Sybase',
  'DB2', 'Firebird', 'Informix', 'H2', 'Access', 'HSQLDB', 'Derby', 'MonetDB',
];

// ── 字符串拼接符（内联检测用） ─────────────────────────────────────────────
// 各 DBMS 字符串串接符（用于字符型参数的内联拼接）
export const INLINE_CONCAT = {
  Oracle: '||',
  PostgreSQL: '||',
  TiDB: '||',
  MySQL: '||', // MySQL 在 ANSI 模式下支持 ||；非 ANSI 时退化为 CONCAT，检测器对回显点本就依赖目标行为
  MariaDB: '||',
  'SQL Server': '+',
  // [⑯] 补全 12 库串接符（InlineQueryDetector 对这些库此前无串接配置）
  SQLite: '||',
  DM8: '||', // Oracle 兼容
  ClickHouse: '||', // CH 支持 || 和 concat()
  DB2: '||',
  Sybase: '+', // 与 SQL Server 一致
  Firebird: '||',
  Informix: '||', // 9.4+ 支持
  H2: '||',
  Access: '&', // Access 用 & 拼接
  HSQLDB: '||',
  Derby: '||',
  MonetDB: '||',
};

export default {
  escSql,
  escBacktick,
  escDq,
  escBracket,
  resolveDbms,
  fromDummy,
  resolveFromClause,
  sanitizeUnionFrom,
  escCols,
  tableRef,
  quoteCol,
  WRAP,
  WRAP_NOCAST,
  HIGH_FREQ_DBMS,
  INLINE_CONCAT,
};

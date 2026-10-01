// =====================================================================
// blindFns.js — 各库盲注二分提取函数（LENGTH / SUBSTRING / ASCII 方言变体）
// 自 extractionMaps.js 拆出（纯搬移）。源码契约测试直接读取本文件文本。
// =====================================================================
// 各库盲注二分提取函数（LENGTH / SUBSTRING / ASCII 等方言变体）
// [⑯] 补全 10 库盲注二分函数（MariaDB/TiDB/DM8 经 resolveDbms 归一化到 MySQL/Oracle）
export const LEN_FN = {
  /** @type {(e: string) => string} */
  MySQL: (e) => `LENGTH((${e}))`,
  /** @type {(e: string) => string} */
  PostgreSQL: (e) => `LENGTH((${e}))`,
  /** @type {(e: string) => string} */
  SQLite: (e) => `LENGTH((${e}))`,
  'SQL Server': (e) => `LEN((${e}))`,
  /** @type {(e: string) => string} */
  Oracle: (e) => `LENGTH((${e}))`,
  /** @type {(e: string) => string} */
  ClickHouse: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  Sybase: (e) => `len((${e}))`,
  /** @type {(e: string) => string} */
  DB2: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  Firebird: (e) => `char_length((${e}))`,
  /** @type {(e: string) => string} */
  Informix: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  H2: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  Access: (e) => `len((${e}))`,
  /** @type {(e: string) => string} */
  HSQLDB: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  Derby: (e) => `length((${e}))`,
  /** @type {(e: string) => string} */
  MonetDB: (e) => `length((${e}))`,
};
export const SUB_FN = {
  /** @type {(e: string, i: string) => string} */
  MySQL: (e, i) => `SUBSTRING((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  PostgreSQL: (e, i) => `SUBSTRING((${e}) FROM ${i} FOR 1)`,
  /** @type {(e: string, i: string) => string} */
  SQLite: (e, i) => `SUBSTR((${e}),${i},1)`,
  'SQL Server': (e, i) => `SUBSTRING((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  Oracle: (e, i) => `SUBSTR((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  ClickHouse: (e, i) => `substring((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  Sybase: (e, i) => `substring((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  DB2: (e, i) => `substr((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  Firebird: (e, i) => `substring((${e}) FROM ${i} FOR 1)`,
  /** @type {(e: string, i: string) => string} */
  Informix: (e, i) => `substr((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  H2: (e, i) => `substring((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  Access: (e, i) => `mid((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  HSQLDB: (e, i) => `substring((${e}),${i},1)`,
  // [P2 审计修复 2026-09-22 真引擎实测] Derby 由 `substring((e) FROM i FOR 1)` 改为 `substr((e),i,1)`。
  // Derby 10.16 真 JDBC 实测：**`SUBSTRING` 根本不是 Derby 的函数名**（三种写法全部报
  //   `Syntax error: Encountered "substring"/"SUBSTRING"`）：
  //     substring((name) FROM 1 FOR 1)  -> Syntax error: Encountered "substring"
  //     substring((name),1,1)           -> Syntax error: Encountered "substring"
  //     SUBSTRING((name),1,1)           -> Syntax error: Encountered "SUBSTRING"
  // 只有 `substr((name),1,1)` 实测返回 [["A"]]。误用会让 Derby 的**布尔盲注数据提取恒失败**
  // （注意：Derby 的拖库通道 data=null 已诚实降级，但盲注通道是独立可达路径）。
  Derby: (e, i) => `substr((${e}),${i},1)`,
  /** @type {(e: string, i: string) => string} */
  MonetDB: (e, i) => `substring((${e}),${i},1)`,
};
export const ASCII_FN = {
  /** @type {(c: string) => string} */
  MySQL: (c) => `ASCII(${c})`,
  /** @type {(c: string) => string} */
  PostgreSQL: (c) => `ASCII(${c})`,
  /** @type {(c: string) => string} */
  SQLite: (c) => `UNICODE(${c})`,
  'SQL Server': (c) => `ASCII(${c})`,
  /** @type {(c: string) => string} */
  Oracle: (c) => `ASCII(${c})`,
  /** @type {(c: string) => string} */
  ClickHouse: (c) => `ascii(${c})`,
  /** @type {(c: string) => string} */
  Sybase: (c) => `ascii(${c})`,
  /** @type {(c: string) => string} */
  DB2: (c) => `ascii(${c})`,
  /** @type {(c: string) => string} */
  Firebird: (c) => `ascii_val(${c})`,
  /** @type {(c: string) => string} */
  Informix: (c) => `ascii(${c})`,
  /** @type {(c: string) => string} */
  H2: (c) => `ascii(${c})`,
  /** @type {(c: string) => string} */
  Access: (c) => `asc(${c})`,
  /** @type {(c: string) => string} */
  HSQLDB: (c) => `ascii(${c})`,
  // [P2 审计修复 2026-09-22 真引擎实测] Derby 原写作 `unicode(c)` —— Derby **没有这个函数**：
  //   SELECT unicode(substr(name,1,1)) FROM b -> 'UNICODE' is not recognized as a function or procedure.
  // 且经穷举确认 Derby **不存在任何「字符→码点」函数**（逐个真机实测，全部报
  //   "is not recognized as a function or procedure"）：ASCII / UNICODE / CODE_POINT / ORD /
  //   ORDINAL / CHAR_CODE / SYSFUN.ASCII / SYSFUN.UNICODE / SYSFUN.CODE_POINT；
  //   `CAST(substr(name,1,1) AS INT)` 亦不可行（Invalid character string format for type INTEGER）。
  // → Derby 的**码点式**二分提取结构性不可用，故显式置 null（结构性不支持，非「未验证」）。
  // 调用方（blindExtractor）已改为：显式 null **不得回落 MySQL**，直接返回 null 诚实降级。
  //
  // 已知可行但**未实施**的替代策略（留档，非本次改动）：Derby 支持字符串比较，
  //   实测 `substr(name,1,1) >= 'A'` / `< 'a'` / `BETWEEN 'A' AND 'Z'` 均返回布尔值，
  //   故可改用「字符序二分」而非「码点二分」重写提取循环——属架构级改动，本次不做。
  Derby: null,
  /** @type {(c: string) => string} */
  MonetDB: (c) => `ascii(${c})`,
};


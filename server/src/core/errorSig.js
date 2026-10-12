// ============================================================================
// core/errorSig.js —— 「响应体在说这是数据库报错」的**唯一真源**
//
// 存在理由（2026-10-12 优化空间勘查 §A1 实锤）：
// 这个语义需求曾有两份正则：
//   · engine/payloads/index.js 的 `ERROR_SIG`（ErrorDetector / SecondOrderDetector /
//     parseErrors / prefilter 消费）—— 漏一项 ⇒ 漏检；
//   · core/scanValidityGuard.js 的 `SQL_ERROR_SIG`（selfInflicted 归类）—— 漏一项 ⇒
//     真实自伤报错计入 serverErrRatio ⇒ 被误判 target_error /「结论不可信」。
// 2026-10-03 曾把后者"补齐为前者同集"，但**只对齐了当时注意到的几条**，其余项持续分叉：
//   仅 ERROR_SIG 有：`unterminated quoted string` / `Unclosed quotation` /
//     `HSQLDB.*(?:error|exception)` / `Derby.*SQLException` / `Informix.*(?:error|exception)` / 裸 `SQLite3`
//   仅 SQL_ERROR_SIG 有：`PG::` / `unrecognized token`
// 且既有漂移守卫（tests/errorSig.specificity.test.js）只钉"固定语料两侧一致命中/不命中"，
// **不校验集合相等** ⇒ 分叉项零覆盖，"同集"注释名不副实。
//
// 治法：收敛为单源。两侧各自 re-export 本常量（保持既有 import 路径与导出名不变），
// 漂移守卫升级为**同一正则对象**断言（ERROR_SIG === SQL_ERROR_SIG）——
// 谁再把字面量抄回任何一侧，立刻红。
//
// 当前集合 = 历史两份的**并集**（逐项人工合并，大小写等价项已折叠：
// `unclosed quotation`≡`Unclosed quotation`、`incorrect syntax near`≡`Incorrect syntax near`；
// `sqlite3\.` 被裸 `SQLite3` 覆盖故弃）。收紧/新增形态时**只改这一处**。
// ============================================================================

/**
 * 通用 SQL 报错特征（跨库）。命中即认为"响应体在陈述数据库报错"。
 * 顺序即文档：先通用后厂商。所有项均为真实引擎报错原文里出现过的形态。
 * @type {RegExp}
 */
export const SQL_ERROR_SIG =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3|syntax error at or near|XPATH syntax error|Incorrect syntax near|near\s+["'][^\n]{0,80}?["']\s*:\s*syntax error|unterminated quoted string|Unclosed quotation|extractvalue|updatexml|conversion failed|unknown column|Division by zero|SQL\d{4}[NRT]|DB2 SQL Error|SQLSTATE\s*\[|PG::|unrecognized token|Adaptive Server|Sybase\s*(?:error|message)|SQL error code|Firebird.*(?:error|exception)|isc_\d+|Informix\s+SQL|Informix.*(?:error|exception)|JdbcSQLException|org\.h2\.jdbc|org\.hsqldb|HSQLDB.*(?:error|exception)|org\.apache\.derby|Derby.*SQLException|Syntax error in SQL statement|Syntax error: Encountered|Cannot parse|Microsoft Access|ODBC|Jet.*Database|MonetDB.*(?:error|exception)|MonetDB\s+\d{5})/i;

export default SQL_ERROR_SIG;

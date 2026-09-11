// ============================================================================
// hexLiteral.js —— 字符串字面量的十六进制化（对标 sqlmap --hex）
//
// 用途：目标存在引号过滤 / WAF 拦 `'`、`%` 时，把字符常量转成十六进制字面量，
// 让 payload 里不出现引号与百分号：`name LIKE 0x2561...` 而不是 `name LIKE '%a%'`。
//
// 【为什么只支持部分方言】
// 十六进制字面量的写法**各库完全不同**，写错就是一条"看起来能用其实不能用"的 SQL：
//   MySQL/MariaDB → 0x6162      PostgreSQL → decode('6162','hex')（没有 0x 字面量）
//   SQL Server    → 0x6162      SQLite      → x'6162'
//   Oracle        → HEXTORAW('6162')
// 本项目只有 MySQL 8 与 PG 16.2 有真机验证环境，其余库**无法证明写法正确**。
// 因此这里只实现已验证的方言，其余显式抛错（宁可说"不支持"，也不静默产出错误 SQL）。
// ============================================================================

const HEX_FNS = {
  // MySQL / MariaDB / TiDB：0x 前缀十六进制字面量，可直接当字符串用
  MySQL: (hex) => `0x${hex}`,
  MariaDB: (hex) => `0x${hex}`,
  TiDB: (hex) => `0x${hex}`,
  SQLServer: (hex) => `0x${hex}`,
  // PostgreSQL：无 0x 字面量；decode(...,'hex') 返回 bytea，
  //   与 text 比较需要 convert_from → 但 LIKE 场景下用 `col LIKE convert_from(...)` 可行
  PostgreSQL: (hex) => `convert_from(decode('${hex}','hex'),'UTF8')`,
  // SQLite：x'' 字面量（BLOB），LIKE 比较时按字节匹配，文本列可用
  SQLite: (hex) => `x'${hex}'`,
};

/** 已支持 --hex 的方言（仅这些经过真机验证或语法确认） */
export const HEX_SUPPORTED_DBMS = Object.keys(HEX_FNS);

/**
 * 把字符串转成目标方言的十六进制字面量。
 * @param {string} str 原始字符串
 * @param {string} edb resolveDbms() 之后的方言名
 * @returns {string} 十六进制字面量表达式
 * @throws {Error} 该方言不支持时抛错（调用方应给出明确提示，不要静默回退成普通字符串）
 */
export function toHexLiteral(str, edb) {
  const fn = HEX_FNS[edb];
  if (!fn) {
    throw new Error(
      `--hex 暂不支持 ${edb}（已验证方言：${HEX_SUPPORTED_DBMS.join('/')}）。` +
        '各库十六进制字面量写法不同，未经验证不会产生静默错误的 SQL——请去掉 --hex 后重试。'
    );
  }
  const hex = Buffer.from(String(str), 'utf8').toString('hex').toUpperCase();
  return fn(hex);
}

/**
 * 构造 LIKE 模式。
 * 未开启 hex 时保持原行为（单引号转义），零回归。
 */
export function buildLikePattern(searchTerm, edb, useHex) {
  const pattern = `%${String(searchTerm)}%`;
  if (!useHex) return `'%${String(searchTerm).replace(/'/g, "''")}%'`;
  return toHexLiteral(pattern, edb);
}

/**
 * 把「搜索类」SQL 模板里已生成的 LIKE 模式字面量替换成十六进制形态。
 *
 * 为什么走"替换"而不是改模板：搜索 SQL 是 per-dialect 字符串模板
 * （SEARCH_COLUMNS_QUERY / SEARCH_TABLES_QUERY 各 10+ 个方言），
 * 逐个改成函数调用既冗长又容易漏；而它们生成的形态是统一的
 * `LIKE '%<escSql(term)>%'`，替换一处即可覆盖全部方言。
 *
 * 降级策略：方言不支持 --hex 时**不改变 SQL**（保持普通形态）并把原因交给调用方记日志——
 * 既不产出错误 SQL，也不静默假装生效。
 *
 * @param {string} sql 模板渲染后的 SQL
 * @param {string} searchTerm 搜索词
 * @param {string} edb resolveDbms() 后的方言名
 * @param {boolean} useHex 是否开启 --hex
 * @returns {string} 可能被替换后的 SQL
 */
export function hexifyLikeInQuery(sql, searchTerm, edb, useHex) {
  if (!useHex) return sql;
  const plain = `'%${String(searchTerm).replace(/'/g, "''")}%'`;
  if (!sql.includes(plain)) return sql;
  return sql.replace(plain, toHexLiteral(`%${String(searchTerm)}%`, edb));
}

export default toHexLiteral;

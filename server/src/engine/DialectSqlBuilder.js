// ============================================================================
// DialectSqlBuilder.js —— 方言 SQL 知识收敛中心（单一事实源）
//
// [D256 2026-11-06] **方言声明化**：18 种 DBMS 的别名归一化、伪表、标识符引号、
// NULL 安全表达式、UNION 包裹模板、串接符、高频顺序全部外置到
// `payloads/dialects.json`；本文件只保留**解释器**（纯函数 + 模板渲染）与输入清洗。
// 新增一种方言 = 在 JSON 加一个条目，不需要改本文件。
//
// 历史实测取证与逐项修正原因（不删历史=不删教训）已归档到
// `docs/方言声明化-D256.md`，包括：
//   · HSQLDB/MonetDB 反引号在真引擎/官方手册下是错的 → 改双引号（2026-09-22）；
//   · Derby CAST(int AS VARCHAR) 需显式长度且须走 COALESCE（真引擎实测）；
//   · MySQL 家族 WRAP 的 COLLATE utf8mb4_bin 防 Illegal mix of collations；
//   · SQL Server 的 escCols 用 [] 而 quoteCol 用双引号、SQLite 反之（既有测试锁定，
//     属历史契约，不得借本次迁移「顺手统一」造成行为漂移）；
//   · ClickHouse/Firebird 的 concat/|| 遇 NULL 整串丢失，需显式兜底。
//
// 等价性判据：`server/tests/dialectSqlBuilder.test.js` 等 12 份方言单测（846 行）
// 是校准过的独立判据，本次迁移**不放宽任何断言**；另有
// `dialectRegistry.guard.test.js` 钉住数据完整性与「源码里不含硬编码方言名」。
//
// 本模块不导入任何 engine 子模块（纯数据 + 纯函数），无循环依赖风险。
// ============================================================================

import dialectData from './payloads/dialects.json' with { type: 'json' };

/** @type {Record<string, any>} */
const DIALECTS = dialectData.dialects;
/** @type {Record<string, any>} */
const DEFAULTS = dialectData.defaults;
/** @type {Record<string, string>} */
const DRIVER_DIALECTS = dialectData.driverDialects;

// 别名模式在模块加载期编译一次（原实现是 3 条 regex 字面量，语义等价：忽略大小写）
const ALIASES = dialectData.aliasPatterns.map((a) => ({
  re: new RegExp(a.pattern, 'i'),
  target: a.target,
}));

/**
 * 读一个方言字段，缺字段回落 defaults（新增方言只写差异项即可）。
 * @param {string} dbms 标准 DBMS 名
 * @param {string} key 字段名
 * @returns {any} 字段值
 */
function field(dbms, key) {
  const spec = DIALECTS[dbms];
  const v = spec ? spec[key] : undefined;
  return v === undefined ? DEFAULTS[key] : v;
}

/**
 * 渲染声明式模板。占位符 ${name} 从 vars 取值；未提供的占位符原样保留，
 * 防止数据里写错名字时静默产出半截 SQL。
 * @param {string} tpl 模板
 * @param {Record<string, string>} vars 变量表
 * @returns {string} 渲染结果
 */
export function renderDialectTemplate(tpl, vars) {
  return String(tpl).replace(/\$\{(\w+)\}/g, (m, k) => (Object.hasOwn(vars, k) ? String(vars[k]) : m));
}

// ── 标识符/字符串转义（输入清洗，不属于方言数据）────────────────────────────
// 库名/表名/列名来自目标数据库自身内容，恶意或异常命名会破坏提取 SQL。
export const escSql = (s) => String(s).replace(/'/g, "''");
export const escBacktick = (s) => String(s).replace(/`/g, '``');
export const escDq = (s) => String(s).replace(/"/g, '""');
export const escBracket = (s) => String(s).replace(/\]/g, ']]');

// ── DBMS 归一化 ────────────────────────────────────────────────────────────
// MariaDB/TiDB 与 MySQL 协议互通、DM8 与 Oracle 兼容、边缘库归一到母库，
// 使检测/提取链路自动获得母库能力，避免「识别为未知库 → 死回退」。
export function resolveDbms(dbms) {
  if (!dbms) return null;
  const key = String(dbms);
  for (const a of ALIASES) {
    if (a.re.test(key)) return a.target;
  }
  return dbms; // 未命中别名时原样返回（含大小写），与旧实现一致
}

/** [⑳] 驱动方言名（小写）→ 标准 DBMS 名 */
export function dialectToDbms(dialect) {
  if (!dialect) return null;
  return DRIVER_DIALECTS[String(dialect).toLowerCase()] || null;
}

// ── 伪表 FROM 子句（DUAL 等价物）────────────────────────────────────────────
export function fromDummy(dbms) {
  return field(String(dbms), 'fromDummy');
}

// [P2-5] --union-from：用户强制指定 FROM 子句时跳过方言自动判定。
// 值先经 sanitizeUnionFrom 清洗（仅允许 [A-Za-z0-9_ .$] 与括号，杜绝注释/分号逃逸）。
export function resolveFromClause(dbms, unionFrom) {
  const uf = sanitizeUnionFrom(unionFrom);
  return uf ? ` FROM ${uf}` : fromDummy(dbms);
}

export function sanitizeUnionFrom(v) {
  if (v == null) return '';
  return String(v).replace(/[^A-Za-z0-9_ .$()]/g, '').trim();
}

// ── 尾部行注释 ─────────────────────────────────────────────────────────────
// tamper 开启时 MySQL 系优先 `#`（CRS 942460 的 \W{4} 会把 `-- -` 判为标点异常）。
// 支持 # 的方言由数据里的 hashComment 标记聚合，新增方言自动纳入。
const HASH_COMMENT_RE = new RegExp(
  Object.keys(DIALECTS).filter((k) => field(k, 'hashComment') === true).join('|'),
  'i',
);
export function commentSuffix(dbms, { tamperEnabled = false } = {}) {
  return tamperEnabled && HASH_COMMENT_RE.test(String(dbms || '')) ? '#' : '-- -';
}

// ── 标识符引用（列名/表名引号）──────────────────────────────────────────────
// 先剥离标识符边界符（防不可信列名穿越），再按方言声明的 open/close 包裹。
export function escCols(cols, dialect) {
  if (!Array.isArray(cols) || cols.length === 0) return '*';
  const q = field(String(dialect), 'identifier');
  return cols.map((c) => {
    const safe = String(c).replace(/[`"\[\]]/g, '');
    return q.open + safe + q.close;
  }).join(',');
}

// [P0-FIX] CONCAT_WS 会跳过 NULL 参数 → 行中任一列 NULL 即整行错位。
export function escColsNN(cols, dialect) {
  if (!Array.isArray(cols) || cols.length === 0) return '*';
  return cols.map((c) => nnExpr(c, dialect)).join(',');
}

// 同 escColsNN，但由调用方指定列间连接符（避免 replace 命中 IFNULL 内部逗号）。
export function escColsNNJoin(cols, dialect, sep) {
  if (!Array.isArray(cols) || cols.length === 0) return '*';
  return cols.map((c) => nnExpr(c, dialect)).join(sep);
}

function nnExpr(col, dialect) {
  const id = escCols([col], dialect);
  return renderDialectTemplate(field(String(dialect), 'nnExpr'), { id });
}

// 表引用构造：模板里 ${dbBt}/${tBt}/${tBr}/${tDq} 是已按方言转义好的变体。
export function tableRef(edb, db, table) {
  const t = String(table);
  const d = String(db);
  return renderDialectTemplate(field(String(edb), 'tableRef'), {
    db,
    t,
    dbBt: escBacktick(d),
    tBt: escBacktick(t),
    tBr: escBracket(t),
    tDq: escDq(t),
  });
}

// 列名引号适配（历史契约：SQL Server 双引号 / SQLite 反引号，与 escCols 不同，勿统一）
export function quoteCol(c, db) {
  const q = field(String(resolveDbms(db)), 'quoteCol');
  return q.open + c + q.close;
}

// CONCAT_WS 堆叠路径版的 NULL 安全列引用（先 normalize DBMS，再按声明渲染）
export function nullSafeQuoteCol(c, db) {
  const id = quoteCol(c, db);
  return renderDialectTemplate(field(String(resolveDbms(db)), 'nullSafeQuoteCol'), { id });
}

// ── UNION 标记包裹（声明式模板 → 函数字典，保持 WRAP[dbms](s) 的既有接口）────
/**
 * @param {'wrap'|'wrapNoCast'} key 模板字段名
 * @returns {Record<string, (s: string) => string>} 函数字典
 */
function buildWrapDict(key) {
  /** @type {Record<string, (s: string) => string>} */
  const out = {};
  for (const [dbms, spec] of Object.entries(DIALECTS)) {
    if (typeof spec[key] === 'string') {
      const tpl = spec[key];
      out[dbms] = (s) => renderDialectTemplate(tpl, { s: String(s) });
    }
  }
  return out;
}

export const WRAP = buildWrapDict('wrap');
// SQL Server / Sybase 的 '+' 遇 int 直接报错，不提供 noCast 变体（调用方回退 WRAP）
export const WRAP_NOCAST = buildWrapDict('wrapNoCast');

// 无回显时按高频库顺序遍历报错/时间签名定库（命中即停）
export const HIGH_FREQ_DBMS = dialectData.highFreq;

// 各 DBMS 字符串串接符（内联检测用）
export const INLINE_CONCAT = Object.fromEntries(
  Object.entries(DIALECTS).map(([k, v]) => [k, v.inlineConcat ?? DEFAULTS.inlineConcat]),
);

export default {
  escSql,
  escBacktick,
  escDq,
  escBracket,
  resolveDbms,
  fromDummy,
  resolveFromClause,
  commentSuffix,
  sanitizeUnionFrom,
  escCols,
  tableRef,
  quoteCol,
  WRAP,
  WRAP_NOCAST,
  HIGH_FREQ_DBMS,
  INLINE_CONCAT,
};

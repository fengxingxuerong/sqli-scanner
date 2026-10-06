// DBMS 版本解析（[P1-FIX 2026-09-05] 版本分支基础设施）
//
// 背景：指纹阶段已从 UNION 回显拿到版本串（DB_VERSION[d].func 的结果），但只用于
// `sig.test(ver)` 定库，版本值本身被丢弃 → 引擎无法按版本选 payload/枚举 SQL。
// 实战影响（真实兼容问题）：
//   · MSSQL：string_agg() 需 2017+，OFFSET/FETCH 需 2012+ —— 内网常见的 2008/2012 全废
//   · MySQL：mysql.user.authentication_string 需 5.7+ —— 5.6 及更早应为 password 列
//   · MySQL：< 5.0 无 information_schema —— 需回退 mysql.* 系统表
//
// 设计：解析为 { major, minor } 数值便于比较；SQL Server 用「年份版本」（2019/2012），
// 其余用「主.次版本」（8.0 / 14.2 / 19 / 3.39）。版本未知 → null（调用方按"最新版"保守处理）。

/** 从版本串提取首个 数字[.数字] 序列 */
function firstNumeric(s) {
  const m = /(\d+)(?:\.(\d+))?/.exec(String(s || ''));
  if (!m) return null;
  return { major: Number(m[1]), minor: m[2] != null ? Number(m[2]) : 0 };
}

/**
 * 解析版本串
 * @param {string} dbms 归一化后的库名（MySQL/SQL Server/PostgreSQL/Oracle/...）
 * @param {string} raw 回显到的原始版本串
 * @returns {{raw:string, major:number|null, minor:number|null}}
 */
export function parseDbmsVersion(dbms, raw) {
  const s = String(raw || '').trim();
  if (!s) return { raw: s, major: null, minor: null };
  const d = String(dbms || '');

  // SQL Server：优先取「SQL Server <年份>」年份版本（2019/2017/2012…），
  // 否则退化为内部版本号 15.0（2019）/ 11.0（2012）等 —— 年份更贴近能力分界。
  if (/sql\s*server/i.test(d)) {
    const ym = /SQL\s*Server\s+(\d{4})/i.exec(s);
    if (ym) return { raw: s, major: Number(ym[1]), minor: 0 };
    const nm = firstNumeric(s);
    if (nm) {
      // 内部版本号 → 年份映射（常用档）
      const map = { 16: 2022, 15: 2019, 14: 2017, 13: 2016, 12: 2014, 11: 2012, 10: 2008, 9: 2005 };
      const year = map[nm.major];
      return { raw: s, major: year ?? nm.major, minor: 0 };
    }
    return { raw: s, major: null, minor: null };
  }

  // Oracle：'Oracle Database 19c' / 'Release 11.2.0.4.0' / 'Oracle Database 11g'
  if (/oracle|dm8|dameng/i.test(d)) {
    const rel = /Release\s+(\d+)\.(\d+)/i.exec(s);
    if (rel) return { raw: s, major: Number(rel[1]), minor: Number(rel[2]) };
    const cm = /(\d{2})[cCgG]\b/.exec(s);
    if (cm) return { raw: s, major: Number(cm[1]), minor: 0 };
    const nm = firstNumeric(s);
    return nm ? { raw: s, major: nm.major, minor: nm.minor } : { raw: s, major: null, minor: null };
  }

  // PostgreSQL：'PostgreSQL 14.2 on x86_64-pc-linux-gnu'
  if (/postgres/i.test(d)) {
    const m = /PostgreSQL\s+(\d+)(?:\.(\d+))?/i.exec(s);
    if (m) return { raw: s, major: Number(m[1]), minor: m[2] != null ? Number(m[2]) : 0 };
  }

  // MySQL/MariaDB/TiDB/SQLite/ClickHouse 等：直接取首个数字序列
  // '8.0.32' → 8.0；'5.7.25-TiDB-v7.5.0' → 5.7；'3.39.4' → 3.39
  const n = firstNumeric(s);
  return n ? { raw: s, major: n.major, minor: n.minor } : { raw: s, major: null, minor: null };
}

/**
 * 版本下界比较：ver >= min
 *   · 支持到**补丁级**（MySQL 的能力分界大量落在补丁号：LATERAL 8.0.14、VALUES ROW 8.0.19、
 *     JSON_VALUE 8.0.21）—— patch 取自 ver.patch，缺省时从 ver.raw 的第三个数字现算
 *     （parseDbmsVersion 一直把原始版本串带在 raw 里，所以解析侧不用改）。
 *   · min 为数字时只到次版本（5.7 → major=5, minor=7）；要表达补丁级下限必须用对象形态
 *     {major, minor?, patch?} —— 8.019 这种小数会被"一位小数"编码静默读成 8.0，schema 已拒。
 * 版本未知（major=null）→ 返回 true（保守按"支持"处理，不因未知版本砍掉 payload）
 */
export function versionAtLeast(ver, min) {
  if (!ver || ver.major == null) return true;
  const v = parts(ver);
  const f = parts(typeof min === 'number' ? numToParts(min) : (min || {}));
  for (let i = 0; i < 3; i++) {
    if (v[i] !== f[i]) return v[i] > f[i];
  }
  return true;
}

/** 取 [major, minor, patch]；patch 缺失时从 raw 现算（`8.0.28` → 28） */
function parts(o) {
  const major = Number(o?.major ?? 0);
  const minor = Number(o?.minor ?? 0);
  let patch = Number(o?.patch ?? 0);
  if (o?.patch == null) {
    const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(o?.raw ?? ''));
    if (m) patch = Number(m[3]);
  }
  return [major, minor, patch];
}

/** 数字形态的下限（只到次版本）：5.7 → {major:5, minor:7} */
function numToParts(n) {
  return { major: Math.floor(n), minor: Math.round((n - Math.floor(n)) * 10) };
}

/**
 * 版本上界比较：ver < max（用于"仅老版本适用"的 payload，如 MySQL<5.7 的 password 列）
 * 版本未知 → 返回 false（未知版本不投放老版本专属 payload，避免误伤）
 */
export function versionBelow(ver, max) {
  if (!ver || ver.major == null) return false;
  const v = parts(ver);
  const c = parts(typeof max === 'number' ? numToParts(max) : (max || {}));
  for (let i = 0; i < 3; i++) {
    if (v[i] !== c[i]) return v[i] < c[i];
  }
  return false;
}

export default parseDbmsVersion;

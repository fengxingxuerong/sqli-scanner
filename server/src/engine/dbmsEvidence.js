// ============================================================================
// dbmsEvidence.js —— 数据库方言「验证等级」单一事实来源
// ============================================================================
// 存在理由（2026-09-10 评估发现）：README 把 18 库说成「3 库真实验证 + 15 库最小适配」，
// 但仓库里实际存在 7 种引擎的真实验证记录（MariaDB 11.4.13 / H2 / HSQLDB / Derby 也在其中）
// ——即**低估**了自身验证范围；而反过来，报告层完全没有「这个库我没真验过」的声明，
// 交付时客户无从判断结论可信度。两个方向的口径都要修。
//
// 本模块作为唯一事实来源：README 分层表、报告 summary、前端提示均从这里取值。
// 升级某方言等级时**必须同时提供 evidence 路径**（可复现的靶场/报告），否则视为无证据。
// ============================================================================

/**
 * 验证等级：
 *   verified      —— 有真实引擎靶场，检测/绕过主链路跑通（含 tamper A/B）
 *   partial       —— 有真实引擎验证记录，但仅覆盖部分通道（如只验了布尔通道）
 *   template-only —— 仅检测/提取模板，**未在任何真实 DBMS 上跑过**，方言可能有偏差
 */
export const DBMS_EVIDENCE = {
  MySQL: { level: 'verified', evidence: 'e2e/real-mysql-lab（真实 8.0.28 / 8.0.37）+ e2e/waf-real' },
  MariaDB: { level: 'verified', evidence: 'e2e/multi-engine-lab/mariadb-verify.mjs（真实 11.4.13）+ e2e/waf-real' },
  PostgreSQL: { level: 'verified', evidence: 'e2e/real-world-lab（PGlite 18.3 真引擎）' },
  SQLite: { level: 'verified', evidence: 'e2e/recall-lab（sql.js WASM 真引擎）' },
  H2: { level: 'partial', evidence: 'e2e/multi-engine-lab（真实 JDBC 内存库，仅布尔通道 × CRS）' },
  HSQLDB: { level: 'partial', evidence: 'e2e/multi-engine-lab（真实 JDBC 内存库，仅布尔通道 × CRS）' },
  Derby: { level: 'partial', evidence: 'e2e/multi-engine-lab（真实 JDBC 内存库，仅布尔通道 × CRS）' },
  TiDB: { level: 'template-only', evidence: null },
  DM8: { level: 'template-only', evidence: null },
  ClickHouse: { level: 'template-only', evidence: null },
  DB2: { level: 'template-only', evidence: null },
  Sybase: { level: 'template-only', evidence: null },
  Firebird: { level: 'template-only', evidence: null },
  Informix: { level: 'template-only', evidence: null },
  Access: { level: 'template-only', evidence: null },
  MonetDB: { level: 'template-only', evidence: null },
  // [批次 5 2026-09-14] SQL Server 2022 Express 本机真机靶场（mssql npm 驱动直拼 SQL）：
  // num/str 双上下文 union/error/boolean 三通道检出（e2e/mssql-lab）
  'SQL Server': { level: 'verified', evidence: 'e2e/mssql-lab（SQL Server 2022 Express 16.0 真机，union/error/boolean 三通道）' },
  Oracle: { level: 'template-only', evidence: null },
};

const LEVEL_TEXT = {
  verified: '真实引擎验证',
  partial: '部分通道真实引擎验证',
  'template-only': '未在真实 DBMS 验证（模板适配）',
};

/**
 * 取某方言的证据等级（未知方言按最保守处理：template-only）。
 * @param {string} dbms
 * @returns {{dbms:string|null, level:string, levelText:string, evidence:string|null, caveat:string|null}}
 */
export function dbmsEvidenceOf(dbms) {
  const key = String(dbms || '');
  const hit = DBMS_EVIDENCE[key] || null;
  const level = hit?.level || 'template-only';
  return {
    dbms: key || null,
    level,
    levelText: LEVEL_TEXT[level],
    evidence: hit?.evidence || null,
    caveat:
      level === 'template-only'
        ? '该方言仅有检测/提取模板，未在任何真实 DBMS 上跑过；结论需人工复核（方言语法、列类型、报错文本均可能有偏差）'
        : level === 'partial'
          ? '仅在真实引擎上验证了部分通道（见 evidence），未覆盖的通道按 template-only 看待'
          : null,
  };
}

/** 按等级分组（供 README / 前端渲染，避免各处硬编清单） */
export function groupByLevel() {
  const out = { verified: [], partial: [], 'template-only': [] };
  for (const [dbms, v] of Object.entries(DBMS_EVIDENCE)) out[v.level].push(dbms);
  return out;
}

export default dbmsEvidenceOf;

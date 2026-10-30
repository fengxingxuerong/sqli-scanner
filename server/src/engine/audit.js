// ============================================================================
// audit.js —— 跨 DBMS 只读安全配置审计执行器（D181，对标 sqlmap `--audit`）
//
// 分工：`auditChecks.js` 只放「查什么 + 怎么判」，本文件负责「怎么跑、怎么记、怎么失败」。
//
// 三条纪律（与检查项表同源，不是口号）：
//   1. 只读：SQL 全部来自 CHECKS_BY_DIALECT 的 `sql` 字段，调用方无法注入别的语句；
//   2. 不猜：查询报错 / 方言未收录 ⇒ 该条标 `unknown` 并带 `reason`，**不计入 pass**；
//   3. 可复现：每条结果带 `sql` 与原始返回，落进报告 `audit` 段与 `audit.json`。
// ============================================================================
import { CHECKS_BY_DIALECT } from './auditChecks.js';

/**
 * @typedef {object} AuditFinding 单条检查结果
 * @property {string} id 检查项 id
 * @property {string} title 人读标题
 * @property {'info'|'low'|'medium'|'high'} severity 命中风险档
 * @property {'pass'|'fail'|'unknown'} status 判定（unknown = 没查成，不算通过）
 * @property {string} detail 判定依据（人读）
 * @property {string} [sql] 实际执行的只读 SQL
 * @property {string} [reason] status=unknown 时的原因
 */

/**
 * 把驱动返回的 `{ rows, columns }`（列为制表符拼接）还原成对象数组。
 * 直接复用驱动形状，避免为审计再造一条取数路径。
 * @param {{rows?: string[], columns?: string[]}} res 驱动原始返回
 * @returns {Array<Record<string, unknown>>} 对象数组
 */
export function rowsToObjects(res) {
  const cols = Array.isArray(res?.columns) ? res.columns : [];
  const rows = Array.isArray(res?.rows) ? res.rows : [];
  if (!cols.length) return [];
  return rows.map((line) => {
    const cells = String(line).split('\t');
    /** @type {Record<string, unknown>} */
    const obj = {};
    cols.forEach((c, i) => { obj[c] = cells[i]; });
    return obj;
  });
}

/**
 * 跑一个方言的全部检查项。
 * @param {object} driver 已连接的驱动（含 `dialect` 与 `query(sql)`）
 * @param {{dialect?: string}} [opts] 方言覆盖（缺省取 `driver.dialect`）
 * @returns {Promise<{dialect: string, findings: AuditFinding[], summary: {total:number,pass:number,fail:number,unknown:number}}>}
 *   审计结果（`unknown` 单独计数，绝不混进 `pass`）
 */
export async function runAudit(driver, opts = {}) {
  const dialect = String(opts.dialect || driver?.dialect || '').toLowerCase();
  const checks = CHECKS_BY_DIALECT[dialect] || [];
  /** @type {AuditFinding[]} */
  const findings = [];
  if (!checks.length) {
    return {
      dialect,
      findings: [{
        id: 'audit-unsupported',
        title: '当前方言无审计检查项',
        severity: 'info',
        status: 'unknown',
        detail: '未收录该方言的只读检查项',
        reason: `dialect=${dialect || '(空)'}`,
      }],
      summary: { total: 1, pass: 0, fail: 0, unknown: 1 },
    };
  }
  for (const c of checks) {
    /** @type {AuditFinding} */
    const base = { id: c.id, title: c.title, severity: c.severity, status: 'unknown', detail: '', sql: c.sql };
    try {
      const res = await driver.query(c.sql);
      const rows = rowsToObjects(res);
      const verdict = c.judge(rows[0]);
      findings.push({ ...base, status: verdict.status, detail: verdict.detail });
    } catch (e) {
      // 权限不足 / 方言不支持 / 语法差异：一律 unknown + 原因（把「没查成」写成「通过」是本仓红线）
      findings.push({ ...base, status: 'unknown', detail: '查询失败，未判定', reason: String(e?.message || e).slice(0, 200) });
    }
  }
  const summary = { total: findings.length, pass: 0, fail: 0, unknown: 0 };
  for (const f of findings) {
    if (f.status === 'pass') summary.pass++;
    else if (f.status === 'fail') summary.fail++;
    else summary.unknown++;
  }
  return { dialect, findings, summary };
}

/**
 * 审计结论的一句话口径（报告与 manifest 共用，避免两处措辞漂移）。
 * @param {{summary:{total:number,pass:number,fail:number,unknown:number}}} audit 审计结果
 * @returns {string} 人读结论
 */
export function auditSentence(audit) {
  const s = audit?.summary || { total: 0, pass: 0, fail: 0, unknown: 0 };
  if (!s.total) return '未执行安全配置审计';
  const parts = [`${s.total} 项检查：通过 ${s.pass}、存在风险 ${s.fail}`];
  if (s.unknown) parts.push(`**未查成 ${s.unknown}**（不等于通过）`);
  return parts.join('，');
}

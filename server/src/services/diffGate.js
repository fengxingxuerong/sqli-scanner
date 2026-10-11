// ============================================================================
// diffGate.js —— diff-aware CI 门禁（[D45 2026-10-11] semgrep 语义：只对新增发现判红）
//
// 为什么需要：安全 CI 被团队弃用的第一原因是**存量噪声**——基线里那 5 个已知漏洞每天把
// 门禁打成红色，第三天所有人开始无脑点重试，第六天有人把 job 直接禁了。diff 门禁的语义：
//   · 新增发现（基线没有的 location:param:technique）→ 判红（exit 2）
//   · 存量仍在（remaining）→ 不判红（exit 0）——它们已经暴露在基线里，PR 没有引入新风险
//   · 本次结论不可信（validity.reliable=false）→ exit 1——门禁拒绝认证「无新增」，
//     **不判红也不假绿**（verdict=inconclusive ≠ 未检出，本仓红线）
//
// 复用口径：diff 计算与 REST `/api/scan/:id/diff` 同源（engine/scanDiff.js，比对键
// location:param:technique——pointId 每次扫描重新生成，不能做键）。
// ============================================================================
import { listScans, readReport } from './scanLedger.js';

/**
 * 目标归一化（auto 基线按目标匹配用）：URL 去 hash、补全形态；非 URL 原样（去 query 片段）。
 * 台账 target 取 report.target.url || baseUrl（含 query），同目标重扫的 URL 在 CI 里是稳定的。
 * @param {string|undefined} t
 * @returns {string}
 */
export function normalizeTarget(t) {
  const s = String(t || '').trim();
  if (!s || s === '-') return '';
  try {
    const u = new URL(s);
    u.hash = '';
    return u.toString();
  } catch {
    return s.replace(/[?#].*$/, '');
  }
}

/**
 * 解析基线 scanId。
 * @param {{diffBase: string, currentScanId: string, currentTarget: string, rows: Array<{scanId:string,target:string}>}} p
 *   rows 为台账 index 行（新→旧，listScans 契约）。
 * @returns {string|null} 基线 scanId；找不到返回 null（调用方必须显式失败，不许静默按无基线放行）
 */
export function findBaselineScanId({ diffBase, currentScanId, currentTarget, rows }) {
  const base = String(diffBase || '').trim();
  if (!base) return null;
  const list = Array.isArray(rows) ? rows : [];
  if (base === 'auto') {
    const want = normalizeTarget(currentTarget);
    if (!want) return null;
    const hit = list.find(
      (r) => r && r.scanId && r.scanId !== currentScanId && normalizeTarget(r.target) === want
    );
    return hit ? hit.scanId : null;
  }
  if (base === currentScanId) return null; // 自己当基线 = 差异恒空，是假认证
  return list.some((r) => r && r.scanId === base) ? base : null;
}

/**
 * 读基线报告：先内存（同进程复测场景）后台账（历史扫描常态）。
 * @param {{baseScanId: string, scanManager?: {getReport: (id: string) => object|null}|null}} p
 * @returns {object|null}
 */
export function resolveBaselineReport({ baseScanId, scanManager }) {
  if (!baseScanId) return null;
  let rep = scanManager && typeof scanManager.getReport === 'function'
    ? scanManager.getReport(baseScanId)
    : null;
  if (!rep) rep = readReport(baseScanId);
  return rep || null;
}

/**
 * 门禁裁决。**不读环境、不发请求**——纯函数，单测钉死三种出口。
 * @param {{diff: object, newReport: object}} p
 * @returns {{code: 0|1|2, gateable: boolean, reason: string}}
 */
export function decideDiffExit({ diff, newReport }) {
  const validity = newReport && newReport.summary && newReport.summary.validity;
  if (validity && validity.reliable === false) {
    return {
      code: 1,
      gateable: false,
      reason:
        `本次扫描结论不可信（validity=${validity.status}）：diff 门禁拒绝认证「无新增发现」——` +
        '修复扫描环境（认证/签名/可达性）后重跑，再以本次为基线',
    };
  }
  const added = (diff && Array.isArray(diff.new)) ? diff.new : [];
  if (added.length > 0) {
    const list = added
      .map((v) => `${v.location || '?'}:${v.param || '?'}:${v.technique || '?'}`)
      .join('、');
    return { code: 2, gateable: true, reason: `新增 ${added.length} 条发现：${list}` };
  }
  const remaining = (diff && Array.isArray(diff.remaining)) ? diff.remaining.length : 0;
  return {
    code: 0,
    gateable: true,
    reason: `无新增发现（基线 ${(diff && diff.base && diff.base.vulnCount) || 0} 条，仍存在 ${remaining} 条已暴露在基线中、不计入门禁）`,
  };
}

/**
 * 供调用方快速取基线 rows（新→旧）。独立导出是为了测试不用 mock scanLedger。
 * @param {number} [limit]
 */
export function recentScanRows(limit = 500) {
  return listScans(limit);
}

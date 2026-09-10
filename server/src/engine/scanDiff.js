// ============================================================================
// scanDiff.js —— 两次扫描的漏洞差异对比（交付场景：修完漏洞证明「确实修好了」）
//
// 比对键 = location:param:technique。
// ⚠️ 不要用 pointId 做键：pointId 每次扫描都是新生成的（如 283e732d），
//    用它比对会把同一个注入点算成「新增 + 已修复」各一条，结论完全失真。
// ============================================================================

const keyOf = (pointsById, vuln) => {
  const p = pointsById.get(vuln.pointId) || {};
  return `${p.location || vuln.location || '?'}:${p.param || vuln.param || '?'}:${vuln.technique || '?'}`;
};

const shape = (pointsById, vuln) => {
  const p = pointsById.get(vuln.pointId) || {};
  return {
    location: p.location || vuln.location || null,
    param: p.param || vuln.param || null,
    technique: vuln.technique || null,
    riskLevel: vuln.riskLevel || null,
    description: vuln.description || vuln.evidence || '',
  };
};

/**
 * 对比两次扫描报告。
 * @param {object} baseReport 基线报告（如修复前那次）
 * @param {object} curReport  当前报告（如修复后）
 * @returns {{fixed:Array, new:Array, remaining:Array, summary:string,
 *            base:object, current:object}}
 */
export function diffReports(baseReport, curReport) {
  const mapOf = (rep) => {
    const pointsById = new Map(((rep && rep.points) || []).map((p) => [p.id, p]));
    const m = new Map();
    for (const v of (rep && rep.vulns) || []) m.set(keyOf(pointsById, v), shape(pointsById, v));
    return m;
  };
  const baseMap = mapOf(baseReport);
  const curMap = mapOf(curReport);

  const fixed = [...baseMap].filter(([k]) => !curMap.has(k)).map(([, v]) => v);
  const added = [...curMap].filter(([k]) => !baseMap.has(k)).map(([, v]) => v);
  const remaining = [...curMap].filter(([k]) => baseMap.has(k)).map(([, v]) => v);

  return {
    base: {
      id: (baseReport && baseReport.scanId) || null,
      finishedAt: (baseReport && baseReport.finishedAt) || null,
      vulnCount: baseMap.size,
      riskLevel: (baseReport && baseReport.riskLevel) || null,
    },
    current: {
      id: (curReport && curReport.scanId) || null,
      finishedAt: (curReport && curReport.finishedAt) || null,
      vulnCount: curMap.size,
      riskLevel: (curReport && curReport.riskLevel) || null,
    },
    fixed,
    new: added,
    remaining,
    summary: `基线 ${baseMap.size} 条 → 本次 ${curMap.size} 条：修复 ${fixed.length}、新增 ${added.length}、仍存在 ${remaining.length}`,
  };
}

export default diffReports;

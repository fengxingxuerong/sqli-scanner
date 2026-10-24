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
//
// [D152 2026-10-25] failSeverities（判红口径，对标 nuclei -severity / semgrep --error 的
// 分级门禁）：CLI `--fail-severities <csv>` 显式给出时才生效；**不传 = 各模式维持既有语义**
// （diff 模式：新增即红，不分级；普通模式：Critical/High 才红）——这是有意保守：分级口径
// 是策略选择，不是引擎事实，默认悄悄改口径 = 换了一批人在不知情下变了门禁含义。
// ============================================================================
import { listScans, readReport } from './scanLedger.js';

/** 判红口径的合法等级（小写、按严重度降序）；parseFailSeverities 的单一取值源。 */
const FAIL_SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low'];

/**
 * 解析 `--fail-severities` 的 CSV 取值（纯函数，CLI 与测试共用，不在此读环境）。
 * @param {string} csv 如 "critical,high" / "medium"
 * @returns {{ok: boolean, severities?: string[], error?: string}}
 *   ok 时 severities 为去重后按严重度降序的合法子集；至少一个等级，否则报错。
 */
export function parseFailSeverities(csv) {
  const raw = String(csv ?? '').trim();
  if (!raw) return { ok: false, error: '--fail-severities 需要值：逗号分隔的等级子集（critical/high/medium/low，如 critical,high）' };
  const parts = raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const bad = parts.filter((p) => !FAIL_SEVERITY_LEVELS.includes(p));
  if (bad.length) {
    return { ok: false, error: `--fail-severities 含未知等级：${bad.join(',')}（合法值 ${FAIL_SEVERITY_LEVELS.join('/')}）` };
  }
  const uniq = [...new Set(parts)].sort((a, b) => FAIL_SEVERITY_LEVELS.indexOf(a) - FAIL_SEVERITY_LEVELS.indexOf(b));
  return { ok: true, severities: uniq };
}

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
 * [D152] 按口径分桶：达口径的新增才判红。gauge 为空 = 不分级（新增即红，[D45] 原语义）。
 * @param {Array<object>} added diff.new 条目（含 riskLevel）
 * @param {Set<string>|null} gauge 小写等级集合
 * @returns {{red: Array<object>, below: number}}
 */
function splitByGauge(added, gauge) {
  if (!gauge) return { red: added, below: 0 };
  const red = added.filter((v) => gauge.has(String(v.riskLevel || '').toLowerCase()));
  return { red, below: added.length - red.length };
}

/** [D152] 判红裁决文案：达口径清单 + 口径标注 + 低于口径计数的如实披露。
 *  @returns {{code: 0|1|2, gateable: boolean, reason: string}} */
function redVerdict({ red, below, gauge }) {
  const list = red
    .map((v) => `${v.location || '?'}:${v.param || '?'}:${v.technique || '?'}${v.riskLevel ? `(${v.riskLevel})` : ''}`)
    .join('、');
  const policy = gauge ? `（判红口径 ${[...gauge].join(',')}）` : '';
  const belowNote = below > 0 ? `；另有 ${below} 条低于口径的新增未判红（明细见 diff.json）` : '';
  return { code: 2, gateable: true, reason: `新增 ${red.length} 条达判红口径${policy}的发现：${list}${belowNote}` };
}

/**
 * 门禁裁决。**不读环境、不发请求**——纯函数，单测钉死三种出口。
 * @param {{diff: object, newReport: object, failSeverities?: string[]}} p
 *   failSeverities：显式判红口径（parseFailSeverities 的产物，小写等级数组）。
 *   缺省 = 不分级：新增即红（[D45] 原语义，保持不变）。
 * @returns {{code: 0|1|2, gateable: boolean, reason: string}}
 */
export function decideDiffExit({ diff, newReport, failSeverities }) {
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
  // [D152] 显式口径给出时，只有「新增且达口径」才判红；低于口径的新增必须如实披露
  // （不判红 ≠ 不存在——diff.json 里全量都在，门禁 reason 不许吞掉它们）。
  const gauge = Array.isArray(failSeverities) && failSeverities.length ? new Set(failSeverities) : null;
  const { red, below } = splitByGauge(added, gauge);
  if (red.length > 0) return redVerdict({ red, below, gauge });
  const remaining = (diff && Array.isArray(diff.remaining)) ? diff.remaining.length : 0;
  const belowNote0 = gauge && below > 0
    ? `（另有 ${below} 条低于口径 ${[...gauge].join(',')} 的新增未判红，明细见 diff.json）`
    : '';
  return {
    code: 0,
    gateable: true,
    reason: `无新增发现（基线 ${(diff && diff.base && diff.base.vulnCount) || 0} 条，仍存在 ${remaining} 条已暴露在基线中、不计入门禁）${belowNote0}`,
  };
}

/**
 * 供调用方快速取基线 rows（新→旧）。独立导出是为了测试不用 mock scanLedger。
 * @param {number} [limit]
 */
export function recentScanRows(limit = 500) {
  return listScans(limit);
}

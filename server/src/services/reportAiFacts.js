// ============================================================================
// reportAiFacts.js —— [D275] AI 报告的「结论口径」事实层
//
// 为什么单独成模块：AI 报告此前只看 target/points/vulns，不看 summary.verdict /
// unverifiedSurfaces / uncoveredSurfaces / dbmsEvidence / triage。于是模型会把
// 「inconclusive（没测成）」写成「未检出」，把「默认 level=1 没测的 cookie/header 面」
// 写成「已测且安全」，把模板适配的 DBMS 写成「已验证」。这些不是文风问题，是把
// 引擎已经如实披露的边界在 AI 报告里重新抹平。
//
// 本模块只做三件事（纯函数，不读 env / 不发请求 / 不写文件）：
//   ① buildBoundaryFacts(report)：把报告里既有的边界字段压成结构化事实；
//   ② renderBoundarySection(facts)：确定性渲染「结论口径与覆盖边界」章节
//      （追加在模型正文之后，**不是模型生成**，所以不能被模型漏写）；
//   ③ boundaryPromptBlock(facts)：给 analyst/writer/reviewer 的短提示块，
//      让模型叙述与引擎口径一致；最终仍以 ② 的确定性章节为准。
//
// 纪律：这里**不产生任何新检测结论**，只引用报告已有字段；字段缺失时显式写「未提供」，
// 不兜底成「无漏洞」。
// ============================================================================

/** 边界章节的稳定标记（幂等追加用；模型正文里出现同名标题不算）。 */
export const BOUNDARY_MARKER = '<!-- engine-boundary -->';

/** 人工裁决状态枚举（与 triage 服务一致；未知状态计入 untagged）。 */
const TRIAGE_STATUSES = ['open', 'confirmed', 'false_positive', 'accepted_risk'];

/**
 * 把「按注入面摊开的未验证面」压成提示/渲染都能直接消费的形状。
 * @param {Array<object>|undefined} list summary.unverifiedSurfaces
 * @returns {Array<{surface:string,label:string,points:number,tested:number,unverified:number,reason:string,sampleParams:string[]}>}
 */
function normalizeUnverified(list) {
  if (!Array.isArray(list)) return [];
  return list
    .filter((s) => s && typeof s === 'object')
    .map((s) => ({
      surface: String(s.surface || 'unknown'),
      label: String(s.label || s.surface || '未知注入面'),
      points: Number(s.points) || 0,
      tested: Number(s.tested) || 0,
      unverified: Number(s.unverified) || 0,
      reason: String(s.reason || '未跑完'),
      sampleParams: Array.isArray(s.sampleParams) ? s.sampleParams.map(String).slice(0, 3) : [],
    }));
}

/**
 * 把「按配置压根没测的注入面」压成可渲染形状。
 * @param {Array<object>|undefined} list summary.uncoveredSurfaces
 * @returns {Array<{surface:string,label:string,hint:string}>}
 */
function normalizeUncovered(list) {
  if (!Array.isArray(list)) return [];
  return list
    .filter((s) => s && typeof s === 'object')
    .map((s) => ({
      surface: String(s.surface || 'unknown'),
      label: String(s.label || s.surface || '未知注入面'),
      hint: String(s.hint || ''),
    }));
}

/**
 * 人工裁决计数。triage 是交付标注，不改检测结论；这里只如实计数。
 * @param {Array<object>|undefined} vulns report.vulns
 * @returns {{open:number,confirmed:number,false_positive:number,accepted_risk:number,untagged:number,total:number}}
 */
export function triageSummary(vulns) {
  const out = { open: 0, confirmed: 0, false_positive: 0, accepted_risk: 0, untagged: 0, total: 0 };
  for (const v of Array.isArray(vulns) ? vulns : []) {
    out.total += 1;
    const st = v && v.triage && v.triage.status;
    if (TRIAGE_STATUSES.includes(st)) out[st] += 1;
    else out.untagged += 1;
  }
  return out;
}

/**
 * 报告里缺了哪些口径字段（用于渲染「未提供」而不是假装完整）。
 * @param {object} report 引擎报告
 * @param {object} s report.summary
 * @returns {string[]} 缺失字段名
 */
function missingFields(report, s) {
  const missing = [];
  if (!s || !s.verdict) missing.push('summary.verdict');
  if (!s || !s.verdictNote) missing.push('summary.verdictNote');
  if (!s || !s.validity) missing.push('summary.validity');
  if (!Array.isArray(report?.vulns)) missing.push('vulns');
  return missing;
}

/**
 * 对象或 null（边界字段全是可选，缺了就按「未提供」处理）。
 * @param {any} v 候选值
 * @returns {object|null} 对象或 null
 */
function asObject(v) {
  return v && typeof v === 'object' ? v : null;
}

/**
 * 非空转字符串，否则 null（不把缺失写成空串）。
 * @param {any} v 候选值
 * @returns {string|null} 字符串或 null
 */
function strOrNull(v) {
  return v ? String(v) : null;
}

/**
 * validity 兼容两种历史位置：summary.validity 优先，其次顶层 validity。
 * @param {object} s report.summary
 * @param {object} r report
 * @returns {object|null} validity
 */
function pickValidity(s, r) {
  return asObject(s.validity) || asObject(r.validity);
}

/**
 * 定库依据（缺失时 null，渲染层会写「未提供」）。
 * @param {object} s report.summary
 * @returns {{dbms:string|null,level:string|null,levelText:string|null,caveat:string|null}|null} 定库事实
 */
function pickDbmsEvidence(s) {
  const d = asObject(s.dbmsEvidence);
  if (!d) return null;
  return {
    dbms: strOrNull(d.dbms),
    level: strOrNull(d.level),
    levelText: strOrNull(d.levelText),
    caveat: strOrNull(d.caveat),
  };
}

/**
 * 浏览器爬取降级事实。
 * @param {object} s report.summary
 * @returns {{reason:string}|null} 降级事实
 */
function pickCrawlFallback(s) {
  const c = asObject(s.crawlBrowserFallback);
  return c ? { reason: String(c.reason || '未提供原因') } : null;
}

/**
 * 把报告边界字段压成结构化事实。
 * @param {object|null|undefined} report 引擎报告（report.json 形态）
 * @returns {object} 边界事实
 */
export function buildBoundaryFacts(report) {
  const r = asObject(report) || {};
  const s = asObject(r.summary) || {};
  const validity = pickValidity(s, r);
  const vulns = Array.isArray(r.vulns) ? r.vulns : [];
  return {
    verdict: strOrNull(s.verdict),
    verdictNote: strOrNull(s.verdictNote),
    reliable: validity ? validity.reliable !== false : null,
    validityStatus: validity ? strOrNull(validity.status) : null,
    validityReason: validity ? strOrNull(validity.reason) : null,
    unverifiedSurfaces: normalizeUnverified(s.unverifiedSurfaces),
    uncoveredSurfaces: normalizeUncovered(s.uncoveredSurfaces),
    crawlBrowserFallback: pickCrawlFallback(s),
    dbmsEvidence: pickDbmsEvidence(s),
    triage: triageSummary(vulns),
    vulnCount: vulns.length,
    noInjectionPoints: s.noInjectionPoints === true,
    missing: missingFields(r, s),
  };
}

/**
 * 一句「结论口径」摘要（渲染/提示共用，避免两套措辞）。
 * @param {object} f buildBoundaryFacts 的返回
 * @returns {string} 摘要
 */
function verdictLine(f) {
  if (!f.verdict) return '报告未提供 summary.verdict —— 不得据此声称「未检出/无漏洞」';
  if (f.verdict === 'inconclusive') {
    return '本次结论不可判定（verdict=inconclusive）——不等于「未检出」，阴性结论不可引用';
  }
  if (f.verdict === 'vulnerability_detected') {
    return `本次检出 ${f.vulnCount} 条漏洞（verdict=vulnerability_detected）`;
  }
  if (f.verdict === 'no_vulnerability_detected') {
    return '本次按当前配置未检出（verdict=no_vulnerability_detected）——引用前必须同时看未验证/未覆盖面';
  }
  return `verdict=${f.verdict}`;
}

/**
 * 可靠性一句话（validity 缺失时明确说「未提供」，不默认可信）。
 * @param {object} f 边界事实
 * @returns {string} 可靠性描述
 */
function reliabilityLine(f) {
  if (f.reliable === null) return '结论可信度：报告未提供 summary.validity（不得默认可信）';
  if (f.reliable === false) {
    return `结论可信度：不可信（validity.status=${f.validityStatus || 'unknown'}${f.validityReason ? `；${f.validityReason}` : ''}）`;
  }
  return `结论可信度：可信（validity.status=${f.validityStatus || 'ok'}）`;
}

/**
 * 未验证/未覆盖/爬取降级/定库/裁决的逐条文案（空数组返回空数组）。
 * @param {object} f 边界事实
 * @returns {string[]} 明细行
 */
function detailLines(f) {
  const out = [];
  if (f.noInjectionPoints) out.push('本次 0 个注入点 = 根本没测，不是「无漏洞」');
  if (f.unverifiedSurfaces.length) {
    out.push(`未验证注入面（${f.unverifiedSurfaces.length} 类）：`
      + f.unverifiedSurfaces.map((s) => `${s.label} ${s.unverified}/${s.points}（${s.reason}）`).join('、'));
  }
  if (f.uncoveredSurfaces.length) {
    out.push(`按当前配置未测的注入面（${f.uncoveredSurfaces.length} 类）：`
      + f.uncoveredSurfaces.map((s) => s.label).join('、'));
  }
  if (f.crawlBrowserFallback) {
    out.push(`浏览器爬取已降级为 HTTP 爬虫（${f.crawlBrowserFallback.reason}）——SPA 的 XHR 注入面可能整体未发现`);
  }
  if (f.dbmsEvidence) {
    const level = f.dbmsEvidence.levelText || f.dbmsEvidence.level || '未标注';
    out.push(`定库依据：${level}${f.dbmsEvidence.dbms ? `（${f.dbmsEvidence.dbms}）` : ''}`
      + `${f.dbmsEvidence.caveat ? `；告警：${f.dbmsEvidence.caveat}` : ''}`);
  }
  const t = f.triage;
  if (t.total > 0) {
    out.push(`人工裁决（不改变检测结论）：open ${t.open} / confirmed ${t.confirmed} / false_positive ${t.false_positive} / accepted_risk ${t.accepted_risk}${t.untagged ? ` / 未标注 ${t.untagged}` : ''}`);
  }
  if (f.missing.length) out.push(`报告缺失字段：${f.missing.join('、')}（缺失不等于「无风险」）`);
  return out;
}

/**
 * 确定性渲染「结论口径与覆盖边界」章节。该章节由引擎字段生成，不是模型正文。
 * @param {object} facts buildBoundaryFacts 的返回
 * @returns {string} Markdown 章节
 */
export function renderBoundarySection(facts) {
  const f = facts || buildBoundaryFacts({});
  const lines = [
    BOUNDARY_MARKER,
    '### 六、结论口径与覆盖边界（引擎事实，非模型生成）',
    '',
    '> 本节由扫描引擎的报告字段确定性生成，不是模型撰写。引用本报告时必须连同本节一起引用。',
    '',
    `- ${verdictLine(f)}`,
    `- ${reliabilityLine(f)}`,
    ...detailLines(f).map((l) => `- ${l}`),
    '- 声明：未验证面 / 未覆盖面的「未检出」不等于「无漏洞」；inconclusive 不等于「未检出」。',
  ];
  return lines.join('\n');
}

/**
 * 给模型看的短口径块（最终仍以确定性章节为准；这里只防模型叙述与引擎口径冲突）。
 * @param {object} facts buildBoundaryFacts 的返回
 * @returns {string} 提示块
 */
export function boundaryPromptBlock(facts) {
  const f = facts || buildBoundaryFacts({});
  const lines = [
    '## 结论口径（引擎事实，必须遵守，禁止改写）',
    `- ${verdictLine(f)}`,
    `- ${reliabilityLine(f)}`,
    ...detailLines(f).map((l) => `- ${l}`),
    '- 禁止把 inconclusive / 未验证面 / 未覆盖面写成「未检出」或「无漏洞」；报告正文必须保留这些边界声明。',
  ];
  return lines.join('\n');
}

/**
 * 提示用紧凑边界事实：短请求的 JSON 预算很小，完整 facts（triage/missing/逐面字段）
 * 会把分析正文挤掉。这里只保留模型必须遵守的判定与覆盖面。
 * @param {object} facts buildBoundaryFacts 的返回
 * @returns {{verdict:string,reliable:boolean|null,unverified:string|null,uncovered:string|null,dbmsCaveat:string|null}} 紧凑事实
 */
export function compactBoundary(facts) {
  const f = facts || {};
  const unv = (f.unverifiedSurfaces || []).map((s) => `${s.surface}:${s.unverified}/${s.points}`).join(',');
  const unc = (f.uncoveredSurfaces || []).map((s) => s.surface).join(',');
  return {
    verdict: f.verdict || 'missing',
    reliable: f.reliable === null || f.reliable === undefined ? null : f.reliable,
    unverified: unv || null,
    uncovered: unc || null,
    dbmsCaveat: f.dbmsEvidence?.caveat || null,
  };
}

/**
 * 短 prompt 用的一行口径（不占预算，但保留 verdict/可靠性/未验证面）。
 * @param {object} facts buildBoundaryFacts 的返回
 * @returns {string} 单行提示
 */
export function boundaryLine(facts) {
  return `结论口径（引擎事实，禁止改写）：${JSON.stringify(compactBoundary(facts))}`;
}

/**
 * 缓存指纹：边界字段变化时不得命中旧缓存（triage / verdict / 覆盖面都会变）。
 * @param {object} facts 边界事实
 * @returns {string} 短指纹
 */
export function boundaryFingerprint(facts) {
  const f = facts || {};
  const payload = JSON.stringify([
    f.verdict,
    f.reliable,
    f.validityStatus,
    f.vulnCount,
    f.noInjectionPoints,
    (f.unverifiedSurfaces || []).map((s) => `${s.surface}:${s.unverified}/${s.points}`),
    (f.uncoveredSurfaces || []).map((s) => s.surface),
    f.crawlBrowserFallback ? 'crawl-fallback' : null,
    f.dbmsEvidence ? `${f.dbmsEvidence.level}:${f.dbmsEvidence.caveat || ''}` : null,
    f.triage,
    f.missing,
  ]);
  // FNV-1a：只用于缓存键，不承担安全语义
  let h = 2166136261;
  for (let i = 0; i < payload.length; i++) {
    h = Math.imul(h ^ payload.charCodeAt(i), 16777619);
  }
  return (h >>> 0).toString(16);
}

export default {
  buildBoundaryFacts,
  renderBoundarySection,
  boundaryPromptBlock,
  boundaryFingerprint,
  compactBoundary,
  boundaryLine,
  triageSummary,
  BOUNDARY_MARKER,
};

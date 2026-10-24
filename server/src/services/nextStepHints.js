// ============================================================================
// nextStepHints.js —— [D153 2026-10-25] 从报告既有披露推导「代理下一步」建议
//
// 为什么：MCP 的调用方是 AI 代理（agentic 形态，对标 2026-W43 热点的 agentic 化趋势，
// 见 docs/竞品对标-2026W43.md 吸收矩阵）。代理最容易犯的错不是不会调工具，而是**把报告
// 读扁**：inconclusive 当成「没洞」、没测的面当成「测了没洞」、误报未裁决就往外报。
// 本模块把 AGENTS §2「代理最容易读错的五件事」翻译成**机器可消费的建议字段**。
//
// 纪律（本模块的边界）：
//   · 只读既有披露字段（validity / verdict / unverifiedSurfaces / uncoveredSurfaces /
//     crawlBrowserFallback / triage / dbmsEvidence / vulns），**不产生任何新检测结论**——
//     建议是对既有披露的引用与排序，不是新事实；
//   · 纯函数：不读环境、不发请求、不查台账（可单测、可在任何取数面上复用）；
//   · 每类建议一个小函数（判空即 null），主函数只做装配——复杂度门禁口径。
// ============================================================================

/**
 * 一条建议：kind 决定代理如何分流处理，via 指向具体可执行入口（工具/旗标/端点）。
 * @typedef {{kind: string, text: string, via: string}} NextStepHint
 */

/** @param {object|null|undefined} validity @returns {NextStepHint|null} */
function hintSession(validity) {
  if (!validity || validity.reliable !== false) return null;
  return {
    kind: 'fix-session',
    text: `本次结论不可信（validity=${validity.status}）——inconclusive ≠ 未检出，阴性结论不可引用`,
    via: '补认证后重扫：run_scan(cookie=…) / CLI --auth --cookie --refresh-url --request-script',
  };
}

/** @param {object} s summary @returns {NextStepHint|null} */
function hintUnverified(s) {
  const list = Array.isArray(s.unverifiedSurfaces) ? s.unverifiedSurfaces : [];
  if (list.length === 0) return null;
  return {
    kind: 'retest-unverified',
    text: `${list.length} 个注入面未完成有效检测（${s.unverifiedSentence || '被拦/网络失败'}）——引用阴性结论必须同时声明它们是未验证面`,
    via: '降并发/换 tamper/调 time-sec 后重扫，或 REST POST /api/scan/:id/point/:pointId/retest 单点复测',
  };
}

/** @param {object} s summary @returns {NextStepHint|null} */
function hintUncovered(s) {
  const list = Array.isArray(s.uncoveredSurfaces) ? s.uncoveredSurfaces : [];
  if (list.length === 0) return null;
  return {
    kind: 'raise-coverage',
    text: `${list.length} 类注入面按当前配置未测（如默认 level=1 的 cookie/header/path/表单）——引用「未检出」必须声明覆盖缺口`,
    via: 'run_scan(level=2|4) / CLI --test-headers --test-path --test-param-names 提升覆盖后重扫',
  };
}

/** @param {object} s summary @returns {NextStepHint|null} */
function hintCrawl(s) {
  if (!s.crawlBrowserFallback) return null;
  return {
    kind: 'crawl-fallback',
    text: '请求了 --crawl-browser 但降级成 HTTP 爬虫——SPA 的 XHR 注入面可能整体未发现',
    via: '检查无头浏览器可用性后重扫（详见 README「浏览器爬取」节）',
  };
}

/** @param {object[]} vulns @returns {NextStepHint|null} */
function hintTriage(vulns) {
  if (vulns.length === 0) return null;
  // attachTriage 恒回填 triage，未处理态是 status='open'——缺形防御也按未裁决算
  const undecided = vulns.filter((v) => !v || !v.triage || v.triage.status === 'open');
  if (undecided.length === 0) return null;
  return {
    kind: 'triage',
    text: `${undecided.length}/${vulns.length} 条发现处于未裁决态（open）——裁决是交付标注不改检测结论，但对外汇报按裁决口径引用`,
    via: 'REST PATCH /api/scan/:id/findings/:findingId/triage（open/confirmed/false_positive/accepted_risk）',
  };
}

/** @param {object} s summary @returns {NextStepHint|null} */
function hintDbms(s) {
  const caveat = s.dbmsEvidence && s.dbmsEvidence.caveat;
  if (!caveat) return null;
  return {
    kind: 'dbms-caveat',
    text: String(caveat),
    via: '对外引用 DBMS 结论时必须同时带上该告警',
  };
}

/** 收尾建议：检出→导出交付；显式阴性且覆盖完整→建 CI 基线（引用既有 diff 门禁，不新造语义）。
 *  @param {object} report @param {object} s summary @param {object[]} vulns @returns {NextStepHint|null} */
function hintWrapup(report, s, vulns) {
  if (vulns.length > 0) {
    return {
      kind: 'export',
      text: `${vulns.length} 条发现可导出交付（含 PoC curl / CVSS / CWE）`,
      via: 'get_report(format=sarif|markdown|html)；CI 形态用 CLI --diff-base auto 做只对新增判红的门禁',
    };
  }
  const covered = (Array.isArray(s.unverifiedSurfaces) ? s.unverifiedSurfaces : []).length === 0
    && (Array.isArray(s.uncoveredSurfaces) ? s.uncoveredSurfaces : []).length === 0;
  const trusted = !s.validity || s.validity.reliable !== false;
  // 基线认证要求显式的阴性 verdict：缺形报告（{}）不许被建议建基线——空 ≠ 覆盖完整
  if (s.verdict === 'no_vulnerability_detected' && covered && trusted) {
    return {
      kind: 'baseline',
      text: '已测面覆盖完整且未检出——可把本次当 CI 门禁基线（后续只对新增判红）',
      via: 'CLI node scripts/one-click-scan.mjs -u <url> --diff-base auto（判红口径可配 --fail-severities）',
    };
  }
  return null;
}

/**
 * 从扫描报告推导下一步建议（按紧迫度排序；无建议时返回空数组）。
 * @param {object|null} report 扫描报告（report.json 形态；缺形字段一律按「无该披露」处理）
 * @returns {NextStepHint[]}
 */
export function nextStepHints(report) {
  if (!report || typeof report !== 'object') return [];
  const s = report.summary || {};
  const vulns = Array.isArray(report.vulns) ? report.vulns : [];
  return [
    hintSession(s.validity),
    hintUnverified(s),
    hintUncovered(s),
    hintCrawl(s),
    hintTriage(vulns),
    hintDbms(s),
    hintWrapup(report, s, vulns),
  ].filter(/** @type {(h: NextStepHint|null) => h is NextStepHint} */ ((h) => h !== null));
}

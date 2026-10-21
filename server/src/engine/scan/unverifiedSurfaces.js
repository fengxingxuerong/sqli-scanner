// ============================================================================
// scan/unverifiedSurfaces.js —— [D123 2026-10-21] 「本次哪些注入面没测成」显形
//
// ── 为什么需要它 ───────────────────────────────────────────────────────────
// WAF 场景下最危险的交付物形态不是「漏检」，而是**「被拦 ⇒ 该点根本没测 ⇒ 报未检出」**。
// 仓库此前已有两道防线（`summary.validity` 与 `verdict=inconclusive`），但都是**整轮级**
// 的粗判据：
//   · validity 看的是「近 N 次请求拦截占比 / 会话是否失效」，是个全局健康度；
//   · verdict 只在「整轮不可信」或「0 注入点」时才转 inconclusive。
// 于是存在一个明确缺口：**目标整体健康、部分注入面被 WAF 吃掉**时，报告仍是
// `verdict=no_vulnerability_detected`，只字不提「有 3 个 header 面其实一条 payload 都没送达」。
// 客户读到的就是「这个站这 8 个注入面都测过、都没问题」——而事实是其中 3 个根本没进去。
//
// 本模块把「注入面 × 是否测成」逐面摊开，产出结构化字段供报告/交付层渲染：
//   summary.unverifiedSurfaces = [{ surface, points, tested, unverified, reason, ... }]
//
// ── 判据（保守，宁少报不虚报）──────────────────────────────────────────────
// ⚠ 关键事实（端到端实测于 D123，别凭直觉写判据）：`fullyTestedPoints.add(point.id)` 在
// `detect.js` 里是**无条件**执行的 —— 检测器被 WAF 拦成 403 时并不抛错，于是该点照常
// 进「跑完」集合。所以**「不在 fullyTestedPoints 里」根本识别不出被拦**（第一版判据就栽在
// 这上面：E2E 用例实测 summary 里没有该字段）。真正的证据是**点级拦截计数**——
// `detect.js` 在每点开测前取 `validity.blockHits` 快照、收尾取差值，落在 `point.blockedRequests`。
//
// 一个注入点算「未验证」须满足下列之一（且不命中、不是有意跳过）：
//   A. `point.blockedRequests > 0` —— 本点发请求期间出现过拦截响应（主力判据）；
//   B. `point.netErr === true` —— 检测器自报/网络层失败（已由引擎记入未决）；
//   C. 它在 `inconclusivePoints` 里 —— 守卫中止导致该点没跑完（整轮级来源）。
// 并同时满足：
//   ① 它在 pointsToScan 里（本轮确实计划要测）；
//   ③ 它没有命中记录（命中了就不叫未验证——已有证据）；
//   ④ 它不是有意跳过（见下）。
//
// 关于 ④：`fullyTestedPoints` 是「引擎认为跑完」的集合，但**被预筛选/静态判据/输入校验有意
// 跳过**的点本来就不会进这个集合（引擎认为「没跑」是正确行为，不是被拦）。这类点如果直接算
// 「未验证」，会在任何开了 `--smart` 的正常扫描上刷出一屏假的「未验证面」，把真信号淹掉。
// 权威标记是注入点上的 `skipReason`（`discover.js:tagSkippedPoints` 与输入校验分支写入，
// 报告 `report.points` 保留全量点）⇒ 本模块**读该字段**，不要求调用方另造一份 set。
// `exceptionPoints` 仍保留为可选补充（给调用方传额外的已知跳过集合，例如 resume 跳过的点）。
//
// ── 与既有字段的关系（不重复造账）──────────────────────────────────────────
//   · `validity.inconclusivePoints` —— 因守卫中止而未完成的点（整轮级），本模块是它的**按面细分**；
//   · `validity.counts.netErrPoints` —— 网络层失败的点，本模块在 reason 里如实标注；
//   · `summary.blockPolicy` —— 「被压制了什么/用了什么链重跑」，本模块回答「压制之后哪些面没结论」。
// ============================================================================

/** 注入面归类：location → 面向客户的表述（报告与文案共用，避免两套真相）。 */
export const SURFACE_LABEL = {
  url: 'URL 查询参数',
  body: 'POST/JSON 表单体',
  header: 'HTTP 请求头',
  cookie: 'Cookie',
  path: 'URL 路径段',
  xml: 'XML 元素名',
};

/** 注入面排序：报告里固定顺序，避免随 Object 键序漂移（交付物 diff 要稳定）。 */
const SURFACE_ORDER = ['url', 'body', 'header', 'cookie', 'path', 'xml'];

/** 出现这些计数时，该面「没测成」的原因必须点明（对症下药 vs 笼统说被拦）。 */
function reasonOf({ blocked, netErr, aborted }) {
  const parts = [];
  if (blocked > 0) parts.push(`${blocked} 个因拦截/守卫中止未跑完`);
  if (netErr > 0) parts.push(`${netErr} 个因网络层失败未跑完`);
  const others = aborted - blocked - netErr;
  if (others > 0) parts.push(`${others} 个未跑完（原因见 summary.validity）`);
  return parts.join('；') || '未跑完';
}

/**
 * 计算「按注入面分组的未验证情况」。
 *
 * @param {object} p
 * @param {Array<object>} [p.points] 本轮计划检测的注入点（含 location/param）
 * @param {Set<string>|Iterable<string>} [p.fullyTested] 引擎认为跑完的点 id
 * @param {Array<object>} [p.vulns] 命中列表（有命中的点不算未验证）
 * @param {Set<string>|Iterable<string>} [p.exceptionPoints] 额外的有意跳过点 id（可选；
 *       主判据是注入点自身的 skipReason，本参数只作补充）
 * @param {Array<string>} [p.inconclusivePoints] 守卫中止导致的未完成点（按面细分来源）
 * @param {Array<string>} [p.netErrPoints] 网络层失败的点
 * @returns {{surfaces: Array<object>, totalUnverified: number, totalPoints: number, affectedSurfaces: number}}
 */
export function summarizeUnverifiedSurfaces({
  points = [],
  fullyTested = [],
  vulns = [],
  exceptionPoints = [],
  inconclusivePoints = [],
  netErrPoints = [],
} = {}) {
  const ctx = buildContext({ fullyTested, vulns, exceptionPoints, inconclusivePoints, netErrPoints });
  const acc = new Map();
  for (const p of points) {
    if (!p || !p.id) continue;
    const row = ensureRow(acc, p);
    row.total += 1;
    classifyPoint(p, row, ctx);
  }
  const surfaces = [...acc.values()].filter((r) => r.unverified > 0).map(toSurfaceRow).sort(bySurfaceOrder);
  return {
    surfaces,
    totalUnverified: surfaces.reduce((n, r) => n + r.unverified, 0),
    totalPoints: points.length,
    affectedSurfaces: surfaces.length,
  };
}

/** 把「哪些点有证据 / 哪些点有意跳过」收敛成几个集合，避免主流程里重复 instanceof 判断。 */
function buildContext({ fullyTested, vulns, exceptionPoints, inconclusivePoints, netErrPoints }) {
  return {
    tested: fullyTested instanceof Set ? fullyTested : new Set(fullyTested || []),
    excepted: exceptionPoints instanceof Set ? exceptionPoints : new Set(exceptionPoints || []),
    inconclusive: new Set(inconclusivePoints || []),
    netErr: new Set(netErrPoints || []),
    hit: new Set((vulns || []).map((v) => v && v.pointId).filter(Boolean)),
  };
}

function ensureRow(acc, p) {
  const surface = SURFACE_LABEL[p.location] ? p.location : (p.location || 'unknown');
  if (!acc.has(surface)) {
    acc.set(surface, {
      surface,
      label: SURFACE_LABEL[surface] || String(surface),
      total: 0, tested: 0, skipped: 0, unverified: 0, blocked: 0, netErr: 0, sample: [],
    });
  }
  return acc.get(surface);
}

/**
 * 单个点的归类（三种状态 + 两种非未验证情形）。
 * ⚠ 刻意**不看** ctx.tested：被拦的点同样在 fullyTested 里（detect.js 无条件 add），
 * 靠它判断会永远判不出未验证 —— 这是第一版判据 E2E 实测失败的原因。
 */
function classifyPoint(p, row, ctx) {
  // 有意跳过优先：引擎自己认为「没跑是对的」，不能算未验证（否则 --smart 会刷一屏假信号）
  if (p.skipReason || ctx.excepted.has(p.id)) { row.skipped += 1; return; }
  if (ctx.hit.has(p.id)) return; // 命中了：已有证据，不算未验证
  const blockedByPoint = Number(p.blockedRequests || 0) > 0;
  const netFailed = p.netErr === true || ctx.netErr.has(p.id);
  const aborted = ctx.inconclusive.has(p.id);
  if (!blockedByPoint && !netFailed && !aborted) { row.tested += 1; return; }
  row.unverified += 1;
  if (netFailed) row.netErr += 1;
  else row.blocked += 1;
  // 样例参数名（最多 3 个，报告里给人指路；不塞全量避免报告膨胀）
  if (row.sample.length < 3 && p.param) row.sample.push(String(p.param));
}

function toSurfaceRow(r) {
  return {
    surface: r.surface,
    label: r.label,
    points: r.total,
    tested: r.tested,
    skipped: r.skipped,
    unverified: r.unverified,
    reason: reasonOf({ blocked: r.blocked, netErr: r.netErr, aborted: r.unverified }),
    sampleParams: r.sample,
  };
}

function bySurfaceOrder(a, b) {
  const ia = SURFACE_ORDER.indexOf(a.surface);
  const ib = SURFACE_ORDER.indexOf(b.surface);
  return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
}

/**
 * 生成一句可直接进报告/交付件的结论文案（无未验证面时返回 null，调用方据此不渲染该段）。
 * 刻意把「未验证」与「已测但未检出」分开说 —— 这正是本模块存在的理由。
 * @param {ReturnType<typeof summarizeUnverifiedSurfaces>} s
 * @returns {string|null}
 */
export function unverifiedSentence(s) {
  if (!s || !s.surfaces || s.surfaces.length === 0) return null;
  const detail = s.surfaces.map((r) => `${r.label} ${r.unverified}/${r.points}`).join('、');
  return (
    `本次有 ${s.totalUnverified} 个注入点未能完成有效检测（分布在 ${s.affectedSurfaces} 类注入面：${detail}）。` +
    '这些点「未检出」不等于「无漏洞」——它们根本没测成，并非被测后判为安全；' +
    '需按 summary.validity.advice 处置后复扫，或在报告中按未验证面单独声明。'
  );
}

// ============================================================================
// scan/oobSentinel.js —— 背景 OOB 哨兵（[D108] 2026-10-19，对标 Collaborator Everywhere）
//
// 补 P1-5：interactsh 已就绪（D87），但 OOB 仍是 **opt-in** —— 只有 techniques 含 oob 且
// risk≥2 时才逐点投放带外载荷；risk=1 会把 oob 从技术集剔除。真实无回显盲注常正好藏在
// 「选定技术不覆盖」的面（被预筛选/静态判定跳过的点、未生成注入点的请求头）⇒ 静默漏检。
//
// 本模块在收尾阶段向这些**没测过的面**非侵入式播撒 OOB token：每个面一个 token、每轮
// 一个 DBMS 候选、全部投放完统一等首个回连。任一回连即确认该面无回显注入。
//
// 边界（诚实口径）：
//   · 只覆盖**已发现/可推导的面**（被跳过点、headerParams、配置的常见头、未测完的点）；
//     不凭空猜参数名。
//   · 每面只投一个 HTTP 模板（有 {CALLBACK} 的）；MySQL 族模板只有 UNC 形态，仅在
//     interactsh 模式下兜底使用（UNC 主机名经 DNS 归因，协作端能记录；本地模式无 SMB
//     监听，投了也是空转）。
//   · 不做 tamper（会破坏回调地址）、不做 DNS 轮（主检测器已有）、不做拖库。
//   · 预算硬上限 maxRequests：补测不得变成请求风暴。
// ============================================================================
import { nanoid } from 'nanoid';
import { oobTunnel } from '../../core/oobTunnel.js';
import { OOB_PAYLOADS, fillPayload, replaceAllLiteral } from '../payloads.js';
import { createInjectionPoint, createVulnerability } from '../models.js';
import { buildInjectionRequest } from '../injection.js';
import { send } from '../detectorSupport/egress.js';
import { logger } from '../../core/logger.js';

/** 允许背景哨兵补测的跳过原因（user-skip 是用户明确要求不动，绝不覆盖） */
const BG_SKIP_REASONS = new Set(['prefilter', 'static', 'input_validation']);

/** 播撒时不得替换的头：报文框架/会话/编码关键头，替换只会打断请求或制造噪声 */
const BG_DENY_HEADERS = new Set([
  'cookie', 'authorization', 'host', 'content-length', 'content-type', 'connection',
  'transfer-encoding', 'accept-encoding', 'content-encoding', 'expect', 'upgrade',
  'proxy-authorization', 'proxy-connection', 'te', 'trailer',
]);

/** 头名字符集：头名要原样写进请求行，任意字符等于给 CRLF 注入/畸形报文开口子 */
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;

/** 未知 dbms 时的候选库（MySQL 族/MariaDB/TiDB 同模板，只留代表；DM8 同 Oracle） */
const BG_DBMS_GROUPS = ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle'];

/**
 * 选一条该库的带外触发模板：优先 HTTP（{CALLBACK}）；MySQL 族只有 UNC 形态，
 * 仅 interactsh 模式兜底（UNC 主机名走 DNS 归因，协作端可记录；本地模式无 SMB 监听）。
 * @param {string} dbms
 * @returns {string|null}
 */
function pickTemplate(dbms) {
  const list = OOB_PAYLOADS[dbms] || [];
  const http = list.find((t) => t.includes('{CALLBACK}'));
  if (http) return http;
  if (oobTunnel.mode === 'interactsh') return list.find((t) => t.includes('{UNC}')) || null;
  return null;
}

/**
 * 头名是否可播撒（格式合法 + 不在拒绝表 + 未被已有点覆盖）。
 * @param {string} name
 * @param {Set<string>} seenNames 已有点/已加入的头名（小写）
 * @returns {boolean}
 */
function isProbeableHeader(name, seenNames) {
  const k = String(name || '').trim();
  if (!HEADER_NAME_RE.test(k)) return false;
  const lower = k.toLowerCase();
  return !BG_DENY_HEADERS.has(lower) && !seenNames.has(lower);
}

/** 已有点里的头名（小写集合）：合成头点前用于去重 */
function existingHeaderNames(points) {
  const names = new Set();
  for (const p of points) {
    if (p && p.location === 'header') names.add(String(p.param || '').toLowerCase());
  }
  return names;
}

/** 该点是否属于背景哨兵可接管的「没测」面（跳过原因白名单 + 排除参数名/cookie） */
function isBackgroundCandidate(p) {
  if (!p || !p.id) return false;
  if (p.location === 'paramName' || p.location === 'cookie') return false;
  return !!p.skipReason && BG_SKIP_REASONS.has(p.skipReason);
}

/**
 * 追加一个面（按 id 去重）；头点同时登记头名，避免同一头重复播撒。
 * @param {object} st { surfaces, added, seen, headerNames }
 * @param {any} p 注入点（合成点会进入 added）
 * @param {boolean} synthetic 是否为本次合成的点
 */
function pushSurface(st, p, synthetic) {
  if (!p || !p.id || st.seen.has(p.id)) return;
  st.seen.add(p.id);
  if (p.location === 'header') st.headerNames.add(String(p.param || '').toLowerCase());
  st.surfaces.push({ kind: p.location === 'header' ? 'header' : 'point', point: p });
  if (synthetic) st.added.push(p);
}

/** (a) 被廉价跳过判定排除的点：预筛选/静态/输入校验 */
function collectSkippedPoints(points, st) {
  for (const p of points) if (isBackgroundCandidate(p)) pushSurface(st, p, false);
}

/** (b)+(c) 请求头面：headerParams 声明的 + 配置的常见头（显式数组覆盖默认） */
function collectHeaderSurfaces(target, oobCfg, st) {
  const bg = (oobCfg && oobCfg.background) || {};
  const declared = Object.entries(target.headerParams || {}).map(([k, v]) => [k, String(v ?? '1')]);
  const configured = (Array.isArray(bg.headers) ? bg.headers : []).map((k) => [k, '1']);
  for (const [k, v] of [...declared, ...configured]) {
    if (!isProbeableHeader(k, st.headerNames)) continue;
    pushSurface(st, createInjectionPoint('header', k, v, { background: true }), true);
  }
}

/** (d) 其余未确认点：oob 已选中且点完整跑过 ⇒ OobDetector 已投过，不重复 */
function collectUntestedPoints(points, fullyTestedPoints, oobFullyTested, st) {
  for (const p of points) {
    if (!p || !p.id || p.confirmed || p.skipReason === 'user-skip') continue;
    if (p.location === 'paramName' || p.location === 'cookie') continue;
    if (oobFullyTested && fullyTestedPoints && fullyTestedPoints.has(p.id)) continue;
    pushSurface(st, p, false);
  }
}

/**
 * 收集背景哨兵可播撒的面（优先级顺序即投放顺序）。
 * @param {object} target
 * @param {any[]} points 全量注入点（report.points 同引用；合成头点会由调用方 push）
 * @param {Set<string>} fullyTestedPoints 一阶完整跑完的点
 * @param {any} oobCfg oob 配置段
 * @param {string[]} selectedTechs 本次选中的技术集
 * @returns {{surfaces: Array<{kind:'point'|'header', point:any}>, added: any[]}}
 */
function collectOobSentinelSurfaces(target, points, fullyTestedPoints, oobCfg, selectedTechs) {
  const st = { surfaces: [], added: [], seen: new Set(), headerNames: existingHeaderNames(points) };
  if (!target || target.mode === 'direct') return { surfaces: st.surfaces, added: st.added };
  const selected = Array.isArray(selectedTechs) ? selectedTechs : [];
  collectSkippedPoints(points, st);
  collectHeaderSurfaces(target, oobCfg, st);
  collectUntestedPoints(points, fullyTestedPoints, selected.includes('oob'), st);
  return { surfaces: st.surfaces, added: st.added };
}

/**
 * 构造播撒计划：面 × DBMS 候选（轮转优先，保证每个面都有一次机会），token 一面一个。
 * @param {Array<{kind:string, point:any}>} surfaces
 * @param {string|null} dbms 已知库则只打该库
 * @param {number} maxRequests 请求预算硬上限
 * @returns {Array<{surface:any, dbms:string, template:string, token:string}>}
 */
function buildOobSentinelPlan(surfaces, dbms, maxRequests) {
  const cap = Math.max(1, Number(maxRequests) || 24);
  const groups = dbms && pickTemplate(dbms) ? [dbms] : BG_DBMS_GROUPS;
  const usable = groups
    .map((g) => ({ dbms: g, template: pickTemplate(g) }))
    .filter((x) => x.template)
    .map((x) => ({ dbms: x.dbms, template: /** @type {string} */ (x.template) }));
  const plans = [];
  // 面优先轮转：预算受限时保证**每个面**都至少投过一次，而不是把预算全花在第一个面上
  for (const surface of surfaces) {
    for (const u of usable) {
      if (plans.length >= cap) return plans;
      plans.push({ surface, dbms: u.dbms, template: u.template, token: nanoid(16) });
    }
  }
  return plans;
}

/**
 * 把回连命中转成漏洞条目（每条命中一个面），并同步标记注入点。
 * @param {any[]} hits 命中的计划项
 * @param {object} deps { scanId, reportGen, eventBus }
 * @returns {any[]}
 */
function toFindings(hits, deps) {
  const out = [];
  for (const plan of hits) {
    const point = plan.surface.point;
    const risk = deps.reportGen.riskOf([createVulnerability(point.id, 'oob', 'Medium', [], '')]);
    const where = `${point.location} ${point.param}`;
    const vuln = createVulnerability(
      point.id,
      'oob',
      risk,
      [plan.payload],
      `OOB 背景哨兵：token=${plan.token} 被目标回连至接收端（未显式测试的面：${where}；DBMS 候选 ${plan.dbms}）`
    );
    vuln.dbms = plan.dbms;
    vuln.oobBackground = true;
    point.confirmed = true;
    point.technique = 'oob';
    point.dbms = plan.dbms;
    out.push(vuln);
    deps.eventBus.emit(deps.scanId, 'detection_found', {
      pointId: point.id,
      technique: 'oob',
      vulnerable: true,
      evidence: vuln.evidence,
      payloads: vuln.payloads,
      riskLevel: risk,
    });
  }
  return out;
}

/**
 * 依次投放计划并等待首个回连；命中后继续短窗排空，尽可能多归因。
 * @param {any[]} plans
 * @param {object} deps { httpClient, target, oobCfg, guard }
 * @returns {Promise<any[]>} 命中的计划项
 */
async function fireAndCollect(plans, deps) {
  const ctx = { config: deps.target.config, guard: deps.guard };
  for (const plan of plans) {
    if (deps.guard && deps.guard.shouldAbort) break;
    const addr = oobTunnel.resolveAddresses(plan.token, deps.oobCfg);
    plan.payload = replaceAllLiteral(
      replaceAllLiteral(
        fillPayload(plan.template, { orig: plan.surface.point.originalValue || '1' }),
        '{CALLBACK}',
        addr.http
      ),
      '{UNC}',
      addr.unc
    );
    try {
      await send(deps.httpClient, ctx, buildInjectionRequest(deps.target, plan.surface.point, plan.payload));
    } catch {
      /* 单个播撒请求失败忽略：其余面仍可能回连 */
    }
  }
  const byToken = new Map(plans.map((p) => [p.token.toLowerCase(), p]));
  const hits = [];
  let remaining = plans.map((p) => p.token);
  const bg = deps.oobCfg.background || {};
  const timeoutMs = Number.isFinite(bg.timeoutMs) ? bg.timeoutMs : 10000;
  let hit = await oobTunnel.waitForAnyToken(remaining, timeoutMs);
  while (hit) {
    const plan = byToken.get(String(hit).toLowerCase());
    if (!plan) break;
    hits.push(plan);
    // 同一面只保留首条命中：多库模板是「同一次回连的不同尝试」，重复计数会虚增漏洞数
    remaining = remaining.filter((t) => {
      const p = byToken.get(t.toLowerCase());
      return p && p.surface !== plan.surface;
    });
    if (!remaining.length) break;
    hit = await oobTunnel.waitForAnyToken(remaining, 500);
  }
  return hits;
}

/**
 * 背景 OOB 哨兵主入口。
 * @param {string} scanId
 * @param {object} target
 * @param {any[]} points 全量注入点（report.points 同引用）
 * @param {Set<string>} fullyTestedPoints
 * @param {string|null} dbms
 * @param {any} oobCfg
 * @param {string[]} selectedTechs
 * @param {object} deps { httpClient, guard, report, scanId, eventBus, reportGen }
 * @returns {Promise<any[]>} 背景哨兵漏洞条目
 */
export async function runOobSentinel(scanId, target, points, fullyTestedPoints, dbms, oobCfg, selectedTechs, deps) {
  const bg = (oobCfg && oobCfg.background) || {};
  if (bg.enabled !== true) return [];
  if (!oobTunnel.isStarted()) return []; // 隧道未就绪：宁可不跑，也不假装测过
  const { surfaces, added } = collectOobSentinelSurfaces(target, points, fullyTestedPoints, oobCfg, selectedTechs);
  if (!surfaces.length) return [];
  // 合成头点必须进 report.points：vulnEnrich 按 pointId 回查注入点上下文
  for (const p of added) points.push(p);
  const plans = buildOobSentinelPlan(surfaces, dbms, bg.maxRequests);
  if (!plans.length) return [];
  logger.info(
    `OOB 背景哨兵：向 ${surfaces.length} 个未测面播撒 ${plans.length} 个带外 token（预算 ${bg.maxRequests ?? 24}）`
  );
  const hits = await fireAndCollect(plans, { ...deps, target, oobCfg });
  const findings = toFindings(hits, deps);
  if (findings.length && deps.report && deps.report.summary && deps.report.summary.noInjectionPoints) {
    // 零注入点扫描经背景哨兵检出 ⇒ 「没测」的结论已不成立，清掉误导性标记
    delete deps.report.summary.noInjectionPoints;
    delete deps.report.summary.noInjectionPointsHint;
  }
  return findings;
}

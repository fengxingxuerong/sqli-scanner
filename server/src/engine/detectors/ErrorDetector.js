import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload, ERROR_SIG, ERROR_SIG_BY_DBMS, dbmsFromError, getClauseTemplates, CLAUSE_PAYLOADS } from '../payloads.js';
import { selectPayloads, orderEntriesByBoundary } from '../payloadRegistry.js';
import { extractErrorContext, extractSqlFragment } from '../parseErrors.js';

// 报错注入检测器
// 思路：注入会触发数据库报错的 Payload，检测响应中是否出现数据库报错特征
export class ErrorDetector extends Detector {
  constructor() {
    super('error');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'error');

    // 基线：先确认原始请求是否本就含报错特征，避免把页面固有报错误判为注入
    const baseRes = await this.send(
      ctx.httpClient,
      ctx,
      this.buildRequest(target, point, point.originalValue || '1'),
      ctx
    );
    const baseBody = String(baseRes?.data ?? '');
    const baseMatch = baseBody.match(ERROR_SIG);

    // 优先使用命中库专属报错 Payload，否则遍历全部库的报错 Payload
    // 差距 3（P0）：dbms 未知时原实现 Object.values(PAYLOADS).flatMap 全库 = 14+库×N 模板连发。
    // 现改为按 ERROR_SIG_BY_DBMS 的高频库优先级顺序取每库首条 error 模板，命中即停（_probeTemplates
    // 内已 break），总量 ≤8 条；clause 轮（level≥2）再补 ORDER BY/HAVING 等子句变体（已截断 10 条）。
    // useRegistry 路径（对标 sqlmap 声明式 <test> 筛选）：config.useRegistry===true 时改用
    // selectPayloads() 按 level/risk/dbms 从声明式注册表筛选，testFilter/testSkip 按 id 过滤；
    // 注册表的 clause 字段统一覆盖子句位置变体，不再单独遍历 CLAUSE_PAYLOADS。
    const useRegistry = ctx.config?.useRegistry === true;
    const templates = this._resolveErrorTemplates(ctx, dbms);

    let hit = await this._probeTemplates(ctx, templates, baseMatch);

    // 子句位置变体轮（对标 sqlmap clause 属性体系）：主模板未命中且 level>=2 时追加
    // （ORDER BY 逗号拼接报错 / MySQL LIMIT PROCEDURE ANALYSE 等；有界，level=1 完全不投放）
    // useRegistry 时由注册表 clause 字段统一筛选，不再单独遍历 CLAUSE_PAYLOADS。
    let fromClause = null;
    if (!hit && !useRegistry && Number(ctx.config && ctx.config.level) >= 2) {
      const clauseDbmsList =
        dbms && CLAUSE_PAYLOADS[dbms] ? [dbms] : ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite'];
      const clauseTpls = [];
      const seen = new Set();
      for (const d of clauseDbmsList) {
        for (const t of getClauseTemplates(d, 'error', { maxPerClause: 2, maxTotal: 4 })) {
          if (!seen.has(t.tpl)) {
            seen.add(t.tpl);
            clauseTpls.push(t);
          }
        }
      }
      // 有界：未知 dbms 时跨 5 库总量截断 10 条（每库每 clause ≤ 2 已截）
      for (const t of clauseTpls.slice(0, 10)) {
        hit = await this._probeTemplates(ctx, [t.tpl], baseMatch);
        if (hit) {
          fromClause = t.clause;
          break;
        }
      }
    }

    if (hit) {
      result.vulnerable = true;
      // P1-D3：dbms 未知时按报错签名反推库（无回显目标的 DBMS 识别补充通道）
      const inferred = dbms || dbmsFromError(hit.match);
      result.dbms = inferred;
      result.evidence = `数据库报错回显：${hit.match}（识别为 ${inferred}）${fromClause ? `［子句位置 ${fromClause}］` : ''}`;
      result.payloads = [hit.payload];
      // [G4 对标 sqlmap --parse-errors] opt-in 开启时，错误响应原文留存 + SQL 上下文片段
      // 写进 result.errorDetail（报告/AI 分析消费）。默认关闭，零行为变化。
      const parseErrors = ctx.config?.parseErrors === true;
      if (parseErrors) {
        const parsed = extractErrorContext(hit.body);
        if (parsed) {
          const sqlFrag = extractSqlFragment(hit.body);
          result.errorDetail = {
            signature: parsed.match,
            context: parsed.context,
            sqlFragment: sqlFrag,
            body: parsed.bodyTruncated,
          };
          // 证据文本追加原文上下文（限量，避免刷屏）
          result.evidence += ` ｜ 错误原文: ${parsed.context.slice(0, 120)}`;
        }
      }
      point.confirmed = true;
      point.technique = 'error';
      point.dbms = inferred;
    }
    return result;
  }

  /**
   * 报错向量模板解析（声明式注册表可选路径）。
   * 默认 false：沿用 pickErrorTemplates 扁平数组（零回归）。
   * config.useRegistry === true 时改用 selectPayloads() 按 level/risk/dbms 筛选
   * 声明式注册表条目（对标 sqlmap level/risk/dbms 过滤语义），返回其 template 字段数组。
   * testFilter / testSkip 直接传入 selectPayloads（子串匹配，大小写不敏感），
   * 不在检测器侧重复 RegExp 过滤，避免语义不一致与正则注入风险。
   * 注册表无命中时回退到 pickErrorTemplates（保证 DM8 等未声明库不空跑）。
   * @param {object} ctx { config }
   * @param {string} dbms
   * @returns {string[]}
   */
  _resolveErrorTemplates(ctx, dbms) {
    if (ctx.config?.useRegistry === true) {
      const cfg = ctx.config || {};
      const level = Number(cfg.level) > 0 ? Number(cfg.level) : undefined;
      const risk = Number(cfg.risk) > 0 ? Number(cfg.risk) : undefined;
      // [G1] 按探测闭合族排序：兼容变体优先（逐模板全池扫描时兼容形态先出结果，
      // 对 WAF 熔断/guard.shouldSkip 更友好；探测误判时全集仍在，零回归）
      const entries = orderEntriesByBoundary(
        selectPayloads({
          dbms,
          technique: 'error',
          level,
          risk,
          testFilter: cfg.testFilter,
          testSkip: cfg.testSkip,
        }),
        ctx.point?.boundary
      );
      const templates = entries.map((e) => e.template);
      // 注册表无命中时回退到扁平数组（保证未声明的 DBMS 不空跑）
      if (templates.length) return templates;
    }
    return pickErrorTemplates(dbms);
  }

  // 逐模板探测：报错命中 + 基线剔除 + 二次发送确认；返回 { payload, match, body } 或 null
  async _probeTemplates(ctx, templates, baseMatch) {
    const { httpClient, target, point } = ctx;
    const orig = point.originalValue || '1';
    for (const tpl of templates) {
      const filled = fillPayload(tpl, { orig });
      const payload = this.obfuscateValue(ctx, filled);
      // [熔断] 目标库已报致命错误（如 PG stack depth）后，跳过多层嵌套子查询——
      // 这类 payload 正是把并发栈深度打爆的主因，库已受损时不能再补刀。
      if (ctx?.guard?.shouldSkip(payload)) continue;
      const res = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), ctx);
      const body = String(res?.data ?? '');
      // [P0-FIX 2026-09-16] 先做「HTML 实体 → URL 解码」两段归一化，再剔除被回显的 payload。
      // 诊断实测：path 注入时响应形如
      //   Cannot GET /api/safe/error&#39;%20AND%20extractvalue(1,concat...
      // 单引号被 Express 404 页转成 **HTML 实体 &#39;**（不是 %27），空格是 %20 —— 只做
      // decodeURIComponent 无法还原，这正是前两次修复失败的原因。
      const match = stripEchoedPayload(body, payload).match(ERROR_SIG);
      if (!match) continue;
      // 基线已存在同样的报错信息 → 视为页面固有，不计入注入
      if (baseMatch && match[0] === baseMatch[0]) continue;
      // 二次确认：再发一次，报错应稳定出现，过滤偶发噪声
      const res2 = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), ctx);
      const body2 = String(res2?.data ?? '');
      if (!body2.match(ERROR_SIG)) continue;
      // [G4] body 随命中返回，供 --parse-errors 原文留存（opt-in 消费）
      return { payload, match: match[0], body };
    }
    return null;
  }
}

export default ErrorDetector;

// 差距 3 修复：dbms 未知时的高频库优先 error 模板选择。
// 顺序取 ERROR_SIG_BY_DBMS（MariaDB→MySQL→PostgreSQL→SQL Server→SQLite→Oracle→…），
// 每库至多取首条 error 模板，总量 ≤8：覆盖最常见 6-8 种库的报错注入，命中即停，
// 避免原实现「无 dbms 时 14+ 库 × N 模板全量连发」的请求爆炸（43+ → ≤8 / 命中 2-4）。
export function pickErrorTemplates(dbms) {
  if (dbms && PAYLOADS[dbms] && Array.isArray(PAYLOADS[dbms].error) && PAYLOADS[dbms].error.length) {
    return PAYLOADS[dbms].error;
  }
  const out = [];
  const seen = new Set();
  const ORDER_MAX = 8;
  for (const { dbms: d } of ERROR_SIG_BY_DBMS) {
    if (out.length >= ORDER_MAX) break;
    if (seen.has(d)) continue;
    seen.add(d);
    const tpls = PAYLOADS[d] && Array.isArray(PAYLOADS[d].error) ? PAYLOADS[d].error : [];
    if (tpls.length) out.push(tpls[0]);
  }
  // 兜底：若高频表未覆盖（理论不发生），回退 MySQL 模板防止空跑
  if (!out.length && PAYLOADS.MySQL && PAYLOADS.MySQL.error.length) out.push(PAYLOADS.MySQL.error[0]);
  return out;
}


/**
 * 把响应归一化成「纯文本」：HTML 实体 → 字符 → URL 解码（两轮，防双重编码）。
 *
 * 为什么需要两段：Express 等框架回显 URL 时会做 HTML 转义，同一个单引号在响应里
 * 既可能是 &#39;（HTML 实体）也可能是 %27（URL 编码），只做其中一种都还原不出来。
 * @param {string} s
 * @returns {string}
 */
function normalizeEcho(s) {
  let t = String(s || '');
  t = t.replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d) || 0))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16) || 0))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, String.fromCharCode(34)).replace(/&apos;/g, String.fromCharCode(39))
    .replace(/&amp;/g, '&');
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(t.replace(/\+/g, ' '));
      if (d !== t) t = d; else break;
    } catch { break; }
  }
  return t;
}

/**
 * 剔除响应中被回显的 payload 原文，避免 payload 自我匹配。
 *
 * [P0-FIX 2026-09-16] 黑盒评测（e2e/blackbox-lab）发现的根因：path 注入时 payload 落在 URL 里，
 * 而 404/错误页普遍回显请求 URL，响应里于是出现 extractvalue / SQL syntax 这类
 * **payload 自带的关键词**，被 ERROR_SIG 匹配，误判成「数据库报错回显」。
 * 实测 --test-path 开启时 7 个安全点有 6 个因此误报，sqlmap 在同题上 0 误报。
 *
 * 要点：必须先归一化（HTML 实体 + URL 解码）再比对 —— 诊断实测响应形如
 *   Cannot GET /api/safe/error&#39;%20AND%20extractvalue(1,concat...
 * 单引号是 HTML 实体、空格是 URL 编码；前两次修复只做 URL 解码，故都无效。
 *
 * 只做字符串剔除，不改变 ERROR_SIG 语义；真报错来自数据库、与 payload 原文不是同一串，不受影响。
 * @param {string} body 响应体
 * @param {string} payload 本次注入的 payload
 * @returns {string}
 */
function stripEchoedPayload(body, payload) {
  if (!body || !payload) return body || '';
  let best = normalizeEcho(body);
  const variants = new Set([payload, normalizeEcho(payload)]);
  try { variants.add(encodeURIComponent(payload)); } catch { /* noop */ }
  for (const v of variants) {
    if (v && v.length > 3) best = best.split(v).join('');
  }
  return best;
}

// ============================================================================
// scan/extractExtended.js —— [D300] 扩展拖库通道：二阶注入 + 盲注 opt-in
//
// 背景（2026-11-18 DVWA high 实测）：一阶 union/error 走 extract.js 的 _extract 拖库，
// 但 DVWA high 的两个注入点分别是 boolean(cookie) 与 second_order(session)——
// 两者都进了 finalVulns，却一个只出版本证明、一个根本没有提取分支，report.data 全空。
//
// 本模块把"能拖库"扩展到这两类通道，且不改任何基线函数体（复杂度门禁 GRACE=0）：
//   · 二阶：命中后用传输适配器把 Extractor 的 UNION 拖库请求改写成
//     「写 payload 到存储点 → 读触发页」，从而复用 dumpAllDatabases 全套枚举/行数/取行能力。
//   · 盲注：opt-in（config.extractScope.blindDump，默认 false），逐字节提 current_user()/database() 等标量，
//     成本极高（单值上百请求），默认关闭以免对目标施压；逐值失败不阻断、不伪装成"已拖库"。
//
// D300 续批收尾（2026-11-18 接手补完 + 靶场复验修正，各项均有守卫/靶场钉住）：
//   ① 适配器取 payload 补 URL query 一路：伪点 location='url' 时 buildInjectionRequest 把
//     payload 拼进 req.url 的 `?id=…`（URL 编码形态），data/params 全空 —— 旧适配器只在
//     data/params 里找 'SELECT' ⇒ 每个请求都判 null ⇒ {status:0} ⇒ 拖库静默全空
//     （"能力在、收不到"，与 E2「枚举动作族仅 CLI 可用」同形的入口缺一半）。
//     现按 URL query 逐参数解码找 /select/i；请求不含注入值时诚实失败 {status:0}。
//   ② 伪点列数尊重 --union-cols：2 列是 DVWA 系触发页的常见形态，其它目标用
//     config.unionCols 覆盖（与检测期 UNION 同一配置键，非法值自然回落 2）。
//   ③ 通道标记诚实化：拖库结果为空（无库/无行/无标量）不写 report.summary.d300Channels，
//     dumpUnconfirmed 照 extract.js 口径进 constraints ——「跑了通道」≠「拖到了数据」。
//   ④ dbms 兜底链（靶场复验发现）：二阶/盲注命中常不带 vuln.dbms（无回显指纹不出来，
//     DVWA blind high 实测 dbms=?）⇒ resolveDbms(null) → 方言表达式表全空 → 通道静默空转。
//     现 vuln.dbms → point.dbms → run.dbms → config.dbms（--dbms 强制）逐级回落；
//     触发页回显列不再硬编第 1 列（走 discoverEchoColumns 现场定位，严格类型库友好）；
//     dump 并发强制串行（适配器共享「最新一条存储值」状态，并发会互相读到对方的探针）。
//   ⑤ 适配器透传触发页真实状态码（靶场复验发现）：PGlite 的 500 错误页把整条 SQL（含
//     SQLISCANNER 标记）回显出来，适配器恒回 200 会骗过 _probeBody 的「标记命中须在
//     非错误响应」判据 ⇒ 回显列探测把错误页当命中 ⇒ 全列"可回显" ⇒ 表达式落 INT 列
//     ⇒ 拖库全线 500 静默空转。现经状态捕获 shim 透传（store/trigger 的真实 status）。
//
// 所有新函数刻意 ≤100 行 / ≤15 复杂度；不碰 extract.js / supplementalRuns.js 的基线函数。
// ============================================================================
import * as eventBus from '../../core/eventBus.js';
import { logger } from '../../core/logger.js';
import { emptyExtractedData } from '../models.js';
import { SYS_DBS, hasData } from '../scanHelpers.js';
import { CURRENT_DB_EXPR, CURRENT_USER_EXPR, VERSION_EXPR } from '../extractionMaps.js';
import { resolveDbms } from '../DialectSqlBuilder.js';

/**
 * 二阶拖库：给 SecondOrderDetector 风格的 ctx，用适配器让 Extractor 走 store→trigger。
 * @returns {Promise<object|null>} extracted 结构（含 databases/tables/columns/rows），失败返回 null
 */
async function extractSecondOrderDump(sm, scanId, ctx) {
  const so = (ctx.config && ctx.config.secondOrder) || {};
  const triggerUrl = ctx.triggerUrl || so.secondUrl;
  if (!triggerUrl || !ctx.point || !ctx.point.actionUrl) return null;
  const adapter = buildStoreTriggerClient(sm, scanId, ctx, triggerUrl);
  if (!adapter) return null;
  const dumpCtx = buildDumpCtx(ctx, adapter.client, triggerUrl);
  const collected = emptyExtractedData();
  try {
    await fillDumps(sm, scanId, dumpCtx, collected);
    eventBus.emit(scanId, 'extraction_progress', {
      db: ctx.dbms, table: null, count: Object.keys(collected.rows).length,
      note: `二阶拖库（存储点 ${ctx.point.param} → 触发页）`,
    });
    return collected;
  } catch (e) {
    logger.warn(`二阶拖库失败：${e.message}`);
    return null;
  }
}

/** 构造"写入存储点→读触发页"的 httpClient 适配器；Extractor 发的每个请求都被转成一次 store+trigger 读回。
 *  触发页真实状态码必须透传（[靶场复验 2026-11-19]）：_probeBody 的「标记命中须发生在非错误响应」
 *  判据靠 status——PGlite 的 500 错误页会把整条 SQL（含 SQLISCANNER 标记）回显出来，若适配器恒回
 *  200，回显列探测会把错误页当命中 ⇒ 全列"可回显" ⇒ 表达式落 INT 列 ⇒ 拖库全线 500 静默空转。 */
function buildStoreTriggerClient(sm, scanId, ctx, triggerUrl) {
  const detector = sm.secondOrderDetector;
  if (!detector || typeof detector._store !== 'function' || typeof detector._trigger !== 'function') return null;
  const soCtx = { ...ctx, triggerUrl };
  const triggerClient = {
    request: async (opts) => {
      // Extractor 把 SQL 探针放在 data/params/url（伪点 location='url' ⇒ 只在 url 的 query）里；
      // 取第一个含注入 SQL 的值作为要存储的 payload
      const payload = pickInjectedValue(opts);
      if (payload == null) return { status: 0, data: '' };
      // 状态码捕获 shim：_store/_trigger 只回 body，真实 HTTP 状态从这里捞（错误页 500 必须透传）
      let lastStatus = null;
      const statusClient = {
        request: async (o) => {
          const r = await ctx.httpClient.request(o);
          lastStatus = r?.status ?? lastStatus;
          return r;
        },
      };
      await detector._store(statusClient, soCtx, payload);
      const body = await detector._trigger(statusClient, soCtx, triggerUrl);
      return { status: lastStatus ?? 200, data: body };
    },
  };
  return { client: triggerClient };
}

/** 从 data/params 的键值集合里挑第一个含 SELECT 的注入值（跳过表单固定字段）。 */
function findSelectValue(bag, skipKeys) {
  if (!bag || typeof bag !== 'object' || Array.isArray(bag)) return null;
  for (const [k, v] of Object.entries(bag)) {
    if (skipKeys && skipKeys.has(String(k).toLowerCase())) continue;
    // 大小写不敏感：lowercase 等大小写 tamper 会把 SELECT 整体变形，标记匹配本就免疫
    if (typeof v === 'string' && /select/i.test(v)) return v;
  }
  return null;
}

/**
 * 从请求 URL 的 query 里挑注入值（[D300] 修正①）。
 * 伪点 location='url' ⇒ buildInjectionRequest 把 payload 拼进 `?id=…`（URL 编码形态），
 * searchParams 读取即解码；无命中/解析失败 → null（诚实失败，不猜）。
 */
function pickFromUrl(url) {
  if (typeof url !== 'string' || !/select/i.test(url)) return null;
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (typeof v === 'string' && /select/i.test(v)) return v;
    }
  } catch { /* 相对串/非 URL 形态 → 跳过 */ }
  return null;
}

/** 从 Extractor 构造的请求里挑出注入值（data 对象 / data 串 / params / url query 四处）。 */
function pickInjectedValue(opts) {
  const data = opts && opts.data;
  const skip = new Set(['submit', 'user_token', 'csrf', 'security']);
  return findSelectValue(data, skip)
    || (typeof data === 'string' && /select/i.test(data) ? data : null)
    || findSelectValue(opts && opts.params, null)
    || pickFromUrl(opts && opts.url);
}

/** 给 Extractor 用的 ctx：注入点在触发页（回显形态），httpClient 换成 store→trigger 适配器。
 *  并发强制串行：适配器走「最新一条存储值」这一**共享可变状态**，表级/库级并发会让 worker
 *  互相读到对方刚存的探针（拖库数据错位）——一阶路径每请求自带 payload 无此问题，二阶必须串行。 */
function buildDumpCtx(ctx, client, triggerUrl) {
  const triggerPoint = {
    ...ctx.point,
    id: `so-${ctx.point.id}`,
    location: 'url',
    param: 'id',
    actionUrl: triggerUrl,
    boundary: "'",
    // 原值用**不命中的哨兵**而非 '1'（[靶场复验 2026-11-19] DVWA sqli high 触发查询带
    // `LIMIT 1`：原值命中行会占掉唯一输出行，标记行被截掉 ⇒ 全程无标记静默空转；
    // 哨兵使第一条查询 0 行，标记行恒排第一，任何外层 LIMIT/单行渲染都不再截断标记）。
    originalValue: '999999999',
    // 回显列**不继承存储点的检测结论**（那是存储页上下文，不是触发页的）——置空后
    // extractScalar 走 discoverEchoColumns 现场探测（逐列文本标记，严格类型库友好，
    // INT 列探测失败自动定位 TEXT 回显列）；探测全失败时 extractScalar 回落第 1 列。
    echoCols: null,
    // 触发页列数在检测期从未被 UNION 实测过（检测跑在存储页）：默认 2（DVWA 系触发页
    // 常见形态），用户可用 --union-cols 覆盖（与检测期同一配置键；非法值回落 2）。
    columns: Number(ctx.config?.unionCols) || 2,
  };
  return {
    httpClient: client, target: ctx.target, point: triggerPoint,
    // dumpConcurrency/dumpDatabaseConcurrency 强制 1：见函数头「共享可变状态」说明
    config: { ...ctx.config, dumpConcurrency: 1, dumpDatabaseConcurrency: 1 },
    dbms: ctx.dbms, scanId: ctx.scanId,
  };
}

/** 复用 Extractor 的枚举 + 全量拖库；系统库按 excludeSysdbs 过滤（与一阶 extractAll 同口径）。 */
async function fillDumps(sm, scanId, dumpCtx, out) {
  const allDbs = await sm.extractor.enumerateDatabases(dumpCtx);
  const exclude = dumpCtx.config?.excludeSysdbs !== false;
  const dbs = exclude ? allDbs.filter((d) => !SYS_DBS.has(String(d).toLowerCase())) : allDbs;
  out.databases = dbs;
  if (!dbs.length) return;
  const dumped = await sm.extractor.dumpAllDatabases(dumpCtx, dbs, {});
  out.tables = dumped.tables;
  out.columns = dumped.columns;
  out.rows = dumped.rows;
  if (dumped.meta) out.meta = dumped.meta;
}

/**
 * [D300] 盲注 opt-in 标量提取：逐字节提 current_user/database/version 填 report.data。
 * 默认关闭（config.extractScope.blindDump !== true 直接返回 null）——盲注逐字节成本极高（单值上百请求），
 * 不在用户显式开启前对目标施压。失败/缺方言表达式返回 null，不伪装成"已拖库"。
 */
async function extractBlindScalars(sm, ctx) {
  if (!ctx || !ctx.config || ctx.config?.extractScope?.blindDump !== true) return null;
  if (!sm.extractor || typeof sm.extractor.extractBoolean !== 'function') return null;
  const db = resolveDbms(ctx.dbms);
  const table = {
    currentUser: CURRENT_USER_EXPR[db],
    currentDb: CURRENT_DB_EXPR[db],
    banner: VERSION_EXPR[db],
  };
  const out = emptyExtractedData();
  for (const [field, expr] of Object.entries(table)) {
    if (!expr) continue;
    try {
      // 失败（null）不写字段：hasData/hasExtendedData 按「有值才算提取到」判
      const v = await sm.extractor.extractBoolean(ctx, expr);
      if (v != null) out[field] = v;
    } catch (e) {
      logger.warn(`盲注标量提取 ${field} 失败：${e.message}`);
    }
  }
  return out;
}

/**
 * [D300] 提取阶段包装层：先跑原 extractPhase（一阶 union/error 拖库 + boolean/time 版本证明），
 * 再补二阶拖库与盲注 opt-in。scanRunner 只改 import 名，函数体行数/复杂度零变化。
 * @param {object} run 扫描运行期上下文（比原 extractPhase 多一个 points 字段）
 */
export async function extractPhaseD300(run) {
  const { extractPhase } = await import('./extract.js');
  await extractPhase(run);
  if (!run.target.config.enableExtract) return;
  await runExtended(run);
}

/** 遍历 finalVulns，对二阶命中做拖库、对盲注命中做 opt-in 标量提取，合并进 extracted。
 * 单漏洞失败不阻断主流程（扩展通道是增益，不是判定链的一环）。 */
async function runExtended(run) {
  const { sm, scanId, finalVulns, extracted, report } = run;
  for (const v of finalVulns) {
    try {
      if (v.technique === 'second_order' && v._d300) {
        await absorb(sm, scanId, extracted, report, extractSecondOrderDump(sm, scanId, buildSoCtx(run, v)));
      } else if ((v.technique === 'boolean' || v.technique === 'time') && run.target.config?.extractScope?.blindDump === true) {
        await absorb(sm, scanId, extracted, report, extractBlindScalars(sm, findCtx(run, v)));
      }
    } catch (e) {
      logger.warn(`[D300] 扩展拖库单漏洞失败（不阻断主流程）：${v.id} ${e.message}`);
    }
  }
}

/** 合并提取结果到 extracted。空结果不标记通道（诚实边界：「跑了通道」≠「拖到了数据」）；
 * dumpUnconfirmed 照 extract.js 口径进 constraints，交付前让人看见。 */
async function absorb(sm, scanId, extracted, report, dataPromise) {
  const data = await dataPromise;
  if (!data || !hasExtendedData(data)) return;
  sm._mergeExtracted(extracted, data);
  report.summary = report.summary || {};
  (report.summary.d300Channels ||= []).push('extended-extract');
  if (Array.isArray(data.meta?.dumpUnconfirmed) && data.meta.dumpUnconfirmed.length) {
    report.summary.constraints = report.summary.constraints || [];
    report.summary.constraints.push(
      `拖库空结果未确认（非空表但提取 0 行，提取通路可能不稳）：${data.meta.dumpUnconfirmed.join('、')} —— 请人工复核`
    );
  }
}

/** hasData 不看 banner —— 盲注标量可能只提回 banner（方言仅版本串可用），也算有效提取。 */
function hasExtendedData(d) {
  return hasData(d) || d.banner != null;
}

/** 用挂在 vuln 上的非枚举 _d300 重建二阶拖库 ctx（不持有 httpClient 引用，避免报告序列化泄漏）。
 *  dbms 兜底链：二阶/盲注命中常不带 vuln.dbms（无回显指纹不出来）——
 *  vuln.dbms → 存储点检测期指纹（point.dbms）→ 扫描级指纹（run.dbms）→ 用户强制 --dbms。 */
function buildSoCtx(run, vuln) {
  const { sm, scanId, target } = run;
  const d = vuln._d300;
  const point = (run.points || []).find((p) => p.id === d.pointId) || { id: d.pointId, param: d.param };
  const rawClient = sm.getScanClient(scanId, target);
  const soCfg = (target.config.secondOrder || {});
  return {
    // 暂停/stop 信号下沉到请求边界（与 supplementalRuns 的 ctxBase 同口径；测试桩无该方法时回落裸客户端）
    httpClient: typeof sm._wrapWithSignal === 'function' ? sm._wrapWithSignal.call(sm, scanId, rawClient) : rawClient,
    target, config: target.config, point,
    dbms: vuln.dbms || point.dbms || run.dbms || target.config?.dbms || null,
    triggerUrl: d.triggerUrl, scanId,
    secondOrder: { ...soCfg, triggerUrls: [d.triggerUrl] },
  };
}

/** 从 foundByPoint 找一阶注入点的原 ctx（盲注标量提取要用 point.boundary 等闭合信息）。
 *  dbms 同 buildSoCtx 的兜底链：一阶命中 vuln.dbms 通常有值，缺省时靠点位/扫描级/用户强制。 */
function findCtx(run, vuln) {
  const hit = run.foundByPoint?.get(vuln.pointId);
  const dbms = vuln.dbms || hit?.point?.dbms || run.dbms || run.target?.config?.dbms || null;
  return hit
    ? { ...hit.ctx, dbms: hit.ctx.dbms || dbms, scanId: run.scanId }
    : { config: run.target.config, dbms, scanId: run.scanId };
}

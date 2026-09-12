import { Scheduler } from '../services/Scheduler.js';
import { emptyExtractedData, createVulnerability } from './models.js';
import { defaults } from '../config/defaults.js';
import * as eventBus from '../core/eventBus.js';
import { ScanSession } from '../core/sessionStore.js';
import { oobReceiver } from '../core/oobReceiver.js';
import { logger } from '../core/logger.js';
import { urlHash, publicReport } from './ScanManager.js';
import { _colGuessCache } from './Extractor.js';
import { dialectToDbms } from './DialectSqlBuilder.js';
import { dnsCache } from '../core/httpClient.js';
import { verifyTamperChains } from '../core/waf/chainVerify.js';
import { DbHealthGuard } from '../core/dbHealthGuard.js';
import { ScanValidityGuard, isNetworkFailureError } from '../core/scanValidityGuard.js';
// [P0 2026-09-09 实战批次] 失效值替换（--invalid-*）+ 已知注入点直通
import { applyInvalidValues } from './invalidValue.js';
import { applyKnownPoints } from './knownPoint.js';
import { summarizeSkipped } from './scanHelpers.js';
// [P1-FIX 2026-09-08 实战批次] 拦截页 → 发包决策的统一裁决入口
import { decideBlockPolicy, isUntrustedVendor } from '../core/waf/blockPolicy.js';
import { OPERATOR_SWAP_CHAINS, FILTER_BYPASS_CHAINS } from '../core/waf/wafRecommend.js';
import { GENERIC_BLOCK_VENDOR } from '../core/waf/blockSignatures.js';
import { dbmsEvidenceOf } from './dbmsEvidence.js';
// [拆分第一批 2026-09-12] runScanLoop 阶段外移（纯搬移，行为不变）
import { supplementalPasses } from './scan/supplemental.js';
import { finalizeReport } from './scan/finalize.js';
import { aggregateVulns } from './scan/aggregate.js';
import { extractPhase } from './scan/extract.js';
import { discoverPoints } from './scan/discover.js';

// 暂停轮询间隔（ms）：扫描暂停时在点边界阻塞等待，避免忙等
const PAUSE_POLL_MS = 300;
// HTTP 请求日志节流间隔（ms）：同一扫描内 http_request 事件最少间隔，防 SSE 高峰期刷屏
const HTTP_LOG_THROTTLE_MS = 250;

/**
 * 扫描流水线主循环：发现注入点 → 预筛选 → 调度检测器 → 聚合漏洞 → 提取数据 → 生成报告。
 * 由 ScanManager._run 委托调用；全程经 EventBus 推送进度事件。
 * @param {import('./ScanManager.js').ScanManager} sm ScanManager 实例
 * @param {string} scanId 扫描 ID
 * @returns {Promise<void>}
 */
export async function runScanLoop(sm, scanId) {
    const s = sm.scans.get(scanId);
    if (!s) return;
    const { target, report } = s;
    // [P0-FIX 2026-09-06] baseUrl 规范化：调用方只给 url 时补齐（real-world-lab verify 等
    // 只传 url 的入口，_crawlForms/_fetchHtml/colGuessScopeKey 等多处依赖 baseUrl，
    // 缺失时表单爬取静默失败 → 二阶存储点为空 → second_order 零检出）
    if (!target.baseUrl && target.url) target.baseUrl = target.url;
    // 按 scanId 注入扫描作用域 HttpClient（独立限速桶，前端 ratePerSec 生效）
    const rawClient = sm.getScanClient(scanId, target);
    // [请求日志] 包一层：请求完成后发 http_request 事件（节流 250ms，URL 脱敏）
    // 直连模式（DirectConnector 无 url 语义）跳过；前端 ProgressView 时间线展示
    const client = rawClient && typeof rawClient.request === 'function' ? rawClient : null;
    // [⑮] 扫描级 AbortSignal：stop() 时 abort，中断所有在途 HTTP 请求
    const scanSignal = sm.getSignal ? sm.getSignal(scanId) : null;
    // [熔断] 守卫需早于 ctxBase 创建（ctxBase 被 ctx 与预筛选/指纹共用）；
    // scheduler 在下方才构造，故用引用变量延迟绑定 onTrip。
    let schedulerRef = null;
    const guard = new DbHealthGuard({
      onTrip: ({ id, hint }) => {
        // 同步压住基准并发，避免 _maybeAdjust 在延迟回落时把并发又抬回原值
        if (schedulerRef) {
          schedulerRef.concurrency = 1;
          schedulerRef.baseConcurrency = 1;
        }
        logger.error(`[db-guard] 目标数据库报致命错误（${id}），并发已降至 1 并停止重型 payload：${hint}`);
        eventBus.emit(scanId, 'db_health_tripped', { id, hint, concurrency: 1 });
      },
    });
    // [P0-FIX 2026-09-08] 结论可信度守卫：与 db-guard 同生命周期（每扫描一个）。
    // 阈值走「常量 + 可选 ctx 覆盖」（config.scanValidity，见 scanValidityGuard.VALIDITY_DEFAULTS），
    // 未动 defaults.js；config.scanValidity.enabled === false 为逃生口（观察完全关闭）。
    const validityCfg = (target.config && target.config.scanValidity) || {};
    const validityEnabled = validityCfg.enabled !== false;
    const validity = new ScanValidityGuard(validityCfg);
    const observeValidity = validityEnabled
      ? (ev) => {
          try {
            validity.observe(ev);
          } catch {
            /* 守卫故障不得影响检测主流程 */
          }
        }
      : () => {};
    // [P0-FIX 2026-09-08] 可信度摘要与「阴性结论」裁定（completed / stopped 两条收尾路径共用）。
    // 核心语义：reliable===false 且 vulns 为空时，报告必须显式声明「未检出 ≠ 无漏洞」，
    // 否则使用者会把「目标挂了/被封/会话过期」读成「这个站没有注入」。
    const applyValidity = (rep, sweep) => {
      // 中止时把「本轮计划检测但未跑完」的点补记为未决（含熔断发生时仍在途的点）
      if (sweep && validity.shouldAbort) {
        for (const p of sweep.points) {
          if (p && p.id && !sweep.done.has(p.id)) validity.addInconclusive(p.id);
        }
      }
      const v = validity.summary();
      rep.validity = v;
      rep.summary = rep.summary || {};
      rep.summary.validity = v;
      const negative = (rep.vulns || []).length === 0;
      const inconclusive = !v.reliable && negative;
      rep.summary.verdict = inconclusive ? 'inconclusive' : 'no_vulnerability_detected';
      rep.summary.verdictNote = inconclusive
        ? `未检出漏洞 ≠ 无漏洞：本次扫描 ${v.reason}；${v.inconclusivePoints.length} 个注入点未完成有效检测，阴性结论不成立，需按建议处置后复扫（${v.advice}）`
        : negative
          ? '目标在本次扫描窗口内可达、未被拦且会话有效，「未检出漏洞」的阴性结论可信度正常（仍建议对高风险参数人工复核）'
          : `本次扫描检出 ${(rep.vulns || []).length} 条漏洞；verdict 仅描述「未检出」类阴性结论的可信度，命中详情见 vulns`;
      if (!v.reliable) eventBus.emit(scanId, 'scan_validity', v);
      // 单注入点扫描可能根本不会再进入调度循环，abort 事件在收尾处补发（与 db-guard 同构），
      // 保证调用方一定能收到中止通知
      if (validity.shouldAbort && !validity._abortLogged) {
        validity._abortLogged = true;
        logger.error(`[validity-guard] ${v.reason}——扫描结果不可信`);
        eventBus.emit(scanId, 'scan_validity_abort', { ...v, scanId });
      }
      return v;
    };

    const ctxBase = {
      guard,
      validity,
      httpClient: client && target.mode !== 'direct'
        ? {
            ...client,
            request: async (opts) => {
              // [⑮] 自动注入扫描级 signal，stop() 时中断在途请求
              // [P0-FIX 2026-09-08] 抛错/空响应必须回流可信度守卫后再原样抛出：
              // 返回值与 signal 行为不变（守卫只观察，不参与决策路径）
              let res = null;
              try {
                res = await client.request(scanSignal ? { ...opts, signal: scanSignal } : opts);
              } catch (e) {
                observeValidity({ req: opts, res: null, error: e });
                throw e;
              }
              observeValidity({ req: opts, res });
              const now = Date.now();
              if (now - (ctxBase._lastHttpLogTs || 0) >= HTTP_LOG_THROTTLE_MS) {
                ctxBase._lastHttpLogTs = now;
                try {
                  const u = new URL(opts.url || '');
                  u.search = '';
                  eventBus.emit(scanId, 'http_request', {
                    method: String(opts.method || 'GET').toUpperCase(),
                    url: `${u.protocol}//${u.host}${u.pathname}`,
                    status: res?.status ?? 0,
                    ms: typeof res?.__networkMs === 'number' ? Math.round(res.__networkMs) : undefined,
                  });
                } catch { /* URL 非法不发日志 */ }
              }
              return res;
            },
            // [sqlmap 对标] --null-connection：HEAD 请求也经扫描级 signal 注入 + 日志节流
            ...(typeof client.headRequest === 'function' ? {
              headRequest: async (url, opts) => {
                let res = null;
                try {
                  res = await client.headRequest(url, scanSignal ? { ...opts, signal: scanSignal } : opts);
                } catch (e) {
                  observeValidity({ req: { ...(opts || {}), url }, res: null, error: e });
                  throw e;
                }
                observeValidity({ req: { ...(opts || {}), url }, res });
                const now = Date.now();
                if (now - (ctxBase._lastHttpLogTs || 0) >= HTTP_LOG_THROTTLE_MS) {
                  ctxBase._lastHttpLogTs = now;
                  try {
                    const u = new URL(url || '');
                    u.search = '';
                    eventBus.emit(scanId, 'http_request', {
                      method: 'HEAD',
                      url: `${u.protocol}//${u.host}${u.pathname}`,
                      status: res?.status ?? 0,
                      ms: typeof res?.__networkMs === 'number' ? Math.round(res.__networkMs) : undefined,
                    });
                  } catch { /* URL 非法不发日志 */ }
                }
                return res;
              },
            } : {}),
          }
        : rawClient,
      config: target.config,
      ...(scanSignal ? { signal: scanSignal } : {}),
    };

    const cfg = target.config || {}; // [拆分3a] 上移：阶段 2/3.4 与 discover 共用
    // 1) 发现注入点 + 点位准备（已抽至 scan/discover.js，纯搬移）
    const { points, pointsToScan, session, restored } = await discoverPoints({
      sm, scanId, target, cfg, ctxBase, rawClient, report,
    });

    // 2) 调度每个注入点（并发池 + 令牌桶限速 + 重试）
    eventBus.emit(scanId, 'scan_phase', { phase: 'detecting', message: `正在检测 ${pointsToScan.length} 个注入点…` });
    const scheduler = new Scheduler(target.config.concurrency, target.config.ratePerSec);
    schedulerRef = scheduler; // [熔断] 绑定守卫的降并发目标
    // pointId -> { point, ctx, found:[{technique, result}] }
    const foundByPoint = new Map();
    // [P0-FIX 2026-09-08] 完整跑完检测循环的点（供可信度守卫计算 inconclusivePoints：
    // 熔断中止时未入本集合的计划点即为「没测完」，不能当成「测了且无漏洞」）
    const fullyTestedPoints = new Set();
    const extracted = emptyExtractedData();
    // WAF 指纹聚合（跨注入点去重，按 vendor 保留最高置信度）；识别数据来自指纹基线，零额外发包
    const wafAgg = new Map();
    // [P0-FIX 2026-09-10] 拦截驱动重跑的落盘快照（函数级声明，确保尾部汇总处可见）
    let blockAdaptiveInfo = null;
    // 指纹共享缓存（按目标 key，存 Promise）：同目标多注入点只跑一次指纹，省 8-9 请求/点
    const fpCache = new Map();
    let dbms = null;
    // [P1-FIX 2026-09-05] 解析出的 DBMS 版本（{major,minor,raw} | null），供 ctx/payload 过滤消费
    let dbmsVersion = null;
    // WAF 重跑共享基线：指纹阶段抓取的 baseline 响应（status/headers/body）供 retry 复用
    let sharedBaseline = null;
    const selectedTechs = sm._selectedTechs(target.config);
    const stackedSelected = selectedTechs.includes('stacked');

    // OOB 带外接收端：仅当 oob 被选中且显式 enabled 时启动（默认关闭，避免意外出站带外）
    const oobCfg = target.config.oob;
    // [P1 2026-09-09] OOB 启动失败 → 记录原因，报告收尾写入 summary.oobUnavailable
    // （此前只 warn，交付报告看不到「oob 没测成」，time/oob 场景会被误读成「无带外」）
    let oobUnavailable = null;
    if (selectedTechs.includes('oob') && oobCfg && oobCfg.enabled) {
      try {
        await oobReceiver.start(oobCfg);
      } catch (e) {
        oobUnavailable = String(e?.message || e);
        logger.warn(`OOB 接收端启动失败，oob 检测将不可用：${oobUnavailable}`);
      }
    }

    await scheduler.run(pointsToScan, async (point) => {
      if (s.cancelled) return;
      // [熔断] 目标库已进入不可恢复状态：剩余点直接跳过。
      // 库已损坏时基线被污染，继续测只会产出脏结果并持续伤害目标。
      if (guard.shouldAbort) {
        if (!guard._abortLogged) {
          guard._abortLogged = true;
          logger.error(`[db-guard] 目标数据库连续报致命错误 ${guard.fatalHits} 次，已中止本次扫描以避免持续伤害`);
          eventBus.emit(scanId, 'db_health_abort', { fatalId: guard.lastFatal?.id, fatalHits: guard.fatalHits });
        }
        return;
      }
      // [P0-FIX 2026-09-08] 可信度守卫熔断：目标已连续无有效响应（挂掉/不可达），
      // 继续投放 payload 只会把「测不通」积累成更多虚假阴性。剩余点逐个记入
      // inconclusivePoints（与「未测」区分），报告层据此拒绝「无漏洞」结论。
      if (validity.shouldAbort) {
        validity.addInconclusive(point && point.id);
        if (!validity._abortLogged) {
          validity._abortLogged = true;
          const v = validity.summary();
          logger.error(`[validity-guard] ${v.reason}——已中止剩余注入点检测，结论不可信`);
          eventBus.emit(scanId, 'scan_validity_abort', { ...v, scanId });
        }
        return;
      }
      // [P1-FIX 2026-09-08] 目标回了 Retry-After 就先等再开下一个点：被限流时继续猛打只会把
      // 封禁时间拉长（且会污染后续点的基线，把「本可测」变成「测不准」）。一次 Retry-After 只退避
      // 一次（consume 取完即清），上限 30s；无 Retry-After 时零开销（行为与历史一致）。
      const backoffMs = typeof validity.consumeBackoffMs === 'function' ? validity.consumeBackoffMs() : 0;
      if (backoffMs > 0) {
        logger.info(`[validity-guard] 目标要求退避，本点暂停 ${backoffMs}ms（Retry-After）`);
        eventBus.emit(scanId, 'scan_validity_backoff', { waitMs: backoffMs, pointId: point?.id });
        const deadline = Date.now() + backoffMs;
        while (Date.now() < deadline && !s.cancelled && !s.paused) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(200, deadline - Date.now())));
        }
        if (s.cancelled) return;
      }
      // [P0-FIX] 暂停等待：扫描暂停时在点边界阻塞（不终止请求、不回收上下文），
      // 等待 resume 或 stop。轮询间隔 PAUSE_POLL_MS，避免忙等。
      while (s.paused && !s.cancelled) {
        await new Promise((resolve) => setTimeout(resolve, PAUSE_POLL_MS));
      }
      if (s.cancelled) return;
      // resume 模式：已完成点跳过（节省请求，恢复历史扫描进度）
      if (session && session.perPoint[point.id] && session.perPoint[point.id].status === 'done') {
        eventBus.emit(scanId, 'point_skipped', { pointId: point.id, reason: 'resume-done' });
        return;
      }

      // [⑳] direct 模式：从驱动 dialect 直接映射 DBMS，作为指纹识别 fallback。
      // DirectConnector 不走 HTTP，响应头识别必然失败 → 原先死回退 MySQL。
      // 现在优先从 driver.dialect 映射正确 DBMS，指纹识别仍跑（猜列数/baseline），但 dbms=null 时回落到 dialect。
      let dialectDbms = null;
      if (target.mode === 'direct' && rawClient && typeof rawClient.getDialect === 'function') {
        try {
          const dialect = await rawClient.getDialect();
          if (dialect) {
            dialectDbms = dialectToDbms(dialect);
            if (dialectDbms) {
              point.dbms = dialectDbms;
              dbms = dialectDbms;
            }
          }
        } catch { /* dialect 获取失败，留给指纹识别处理 */ }
      }
      // [Phase6-FIX] 仅当一阶技术被选中时才执行指纹识别/boundary 探测——
      // 二阶-only 扫描无需指纹/boundary，且这些步骤会向存储点发 ORDER BY payload，
      // 污染二阶靶场的 stored value，导致二阶检测器 baseline 已含报错而判定失败。
      const _hasFirstOrder = selectedTechs.some(t => ['union', 'error', 'boolean', 'time', 'stacked', 'inline'].includes(t));

      // [CRS-FIX 2026-09-10] 闭合上下文探测**必须在指纹之前**。
      // 原顺序（先指纹、后 boundary）是列数猜测错误的根因：
      //   指纹的 ORDER BY 二分探针若无闭合前缀，在字符串型注入点上整条 ORDER BY 落在引号内
      //   → SQL 永远合法 → 二分永不收敛 → 列数猜到 maxCols 上限（实测 /str、/like、/blind 猜成 50）
      //   → 该错值经 _colGuessCache 共享给 UnionDetector → UNION 全线 50 列空转（每条都
      //     "different number of columns"）→ 这四个场景 union 技术位恒 0。
      // 提前后指纹与 UnionDetector 用同一套闭合前缀，列数一致，缓存共享才成立。
      // 请求数不变（原本每个点也只探测一次），仅顺序调整。
      if (_hasFirstOrder && point.boundary == null && !point.boundaryProbed) {
        point.boundaryProbed = true;
        try {
          // 用构造函数名查找 UnionDetector（避免依赖 detectors[0] 构造顺序）
          const unionDetector = sm.detectors.find(d => d.constructor.name === 'UnionDetector' || d.constructor.name === 'Detector');
          if (!unionDetector) throw new Error('未找到 UnionDetector');
          // 此处 detectedDbms 尚未算出（TDZ），只能用 direct 模式的 dialect 映射结果
          point.boundary = await unionDetector.probeBoundary({
            ...ctxBase,
            target,
            point,
            dbms: dialectDbms || point.dbms,
          });
        } catch {
          point.boundary = '';
        }
      }

      // [sqlmap 对标] --dbms：用户显式指定 DBMS 时跳过指纹识别（省 8-9 请求/点 + 语义确定），
      // 直接按指定库构造 payload/提取语句。指纹阶段仅在不指定时运行。
      const forcedDbms = (cfg.dbms && String(cfg.dbms).trim()) || null;
      // 指纹识别（返回 { dbms, baseline }，baseline 供 WAF 识别复用）。
      // 同目标多注入点共享：首点跑完整指纹（8-9 请求），后续点命中缓存零额外指纹请求。
      let fpResult = null;
      if (_hasFirstOrder && !forcedDbms) {
        fpResult = await sm._fingerprintCached(fpCache, ctxBase, target, point);
      }
      let detectedDbms = forcedDbms || (fpResult && fpResult.dbms);
      // [⑳] 指纹识别未命中时，回落到 direct 模式 dialect 映射的 DBMS（避免死回退 MySQL）
      if (!detectedDbms) detectedDbms = dialectDbms;
      // [P1-1] 保存 baseline 供 WAF 重跑复用（fpResult.baseline 零额外发包抓取的基线响应）
      if (fpResult && fpResult.baseline) sharedBaseline = fpResult.baseline;
      if (detectedDbms) {
        point.dbms = detectedDbms;
        dbms = detectedDbms;
      }
      // [P1-FIX 2026-09-05] 版本流转：指纹解析出的版本挂到 ctx（点级共享），供
      // payloadRegistry 版本过滤与 extractionMaps 版本分支消费（未知版本为 null）
      if (fpResult && fpResult.version) {
        point.dbmsVersion = fpResult.version;
        dbmsVersion = fpResult.version;
      }
      // WAF 指纹识别：复用指纹阶段已抓取的基线响应（status/headers/body），零额外发包
      const wafCands = sm.wafIdentifier.identify((fpResult && fpResult.baseline) || {});
      for (const c of wafCands) {
        const prev = wafAgg.get(c.vendor);
        if (!prev || c.confidence > prev.confidence) wafAgg.set(c.vendor, c);
      }
      // [sqlmap 对标] 主动 WAF 探测：被动识别无果且 config.activeWafProbe 开启时，
      // 主动发送 WAF 触发 payload 观察拦截响应以识别厂商。仅 direct 模式外触发。
      if (wafCands.length === 0 && cfg.activeWafProbe === true && target.mode !== 'direct') {
        try {
          const probeResult = await sm.wafIdentifier.activeProbe(target, ctxBase.httpClient);
          if (probeResult.detected) {
            const vendor = probeResult.vendor || 'unknown';
            wafAgg.set(vendor, { vendor, confidence: probeResult.confidence, evidence: 'active probe' });
            logger.info(`主动 WAF 探测命中：${vendor}（confidence=${probeResult.confidence}）`);
          }
        } catch (e) {
          logger.warn(`主动 WAF 探测失败：${e.message}`);
        }
      }
      // 注：闭合上下文探测已上移至指纹之前（见 [CRS-FIX 2026-09-10]），此处不再重复。

      const ctx = {
        ...ctxBase,
        target,
        point,
        dbms: detectedDbms || point.dbms,
        // [P1-FIX 2026-09-05] 版本随 ctx 下发（点级，跨检测器/提取器共享）
        dbmsVersion: point.dbmsVersion || dbmsVersion || null,
        // 同点共享基线：后续检测器/提取器可消费此字段复用，避免各自重测 baseline
        baseline: (fpResult && fpResult.baseline) || null,
        extractor: sm.extractor,
        // scanId 透传给 Extractor：盲注常见值缓存（predictOutput）按 scanId+target 维度隔离
        scanId,
        // [Feature 4] session 透传给 Extractor：dumpData 行级断点续传
        session: session || null,
      };

      // 检测器调度：分两层并行，兼顾「经典技术快速抢断省请求」与「慢速采样(time/stacked/oob)并行提速」。
      // 层1 快速回显/布尔层：union / error / boolean / inline —— 这些命中即典型注入，命中后（stacked 未选时）无需再跑慢速层，省请求。
      // 层2 慢速采样层：time / stacked / oob —— 各自需多次采样或独立确认，彼此无依赖，层内并行（墙钟≈单检测器耗时而非累加）。
      // 仅当 stacked 也被选中时，即使层1命中仍跑层2（确保末位 stacked 能独立确认）。
      // 注意：runLayer 仅执行 FAST/SLOW 数组内的技术；任何新加的 SQLi 技术必须加入二者之一，否则不会被调度（inline 即如此接入）。
      const FAST = ['union', 'error', 'boolean', 'inline'];
      const SLOW = ['time', 'stacked', 'oob'];
      const active = sm.activeDetectors(target.config);
      const runLayer = async (techniques) => {
        const inLayer = active.filter((d) => techniques.includes(d.technique));
        const results = await Promise.all(
          inLayer.map(async (detector) => {
            eventBus.emit(scanId, 'point_testing', { pointId: point.id, technique: detector.technique });
            try {
              const result = await detector.detect(ctx);
              // [P0-FIX 2026-09-09] 检测器自报「本点未得出有效结论」（对照对全部不可用）时，
              // 该点计入未决：reliable=false + 报告拒绝下「无漏洞」结论。
              if (result && result.inconclusive) {
                if (validityEnabled) validity.addNetworkErrorPoint(point.id);
                point.netErr = true;
                point.unverifiedReason = String(result.inconclusiveReason || '响应不可用');
              }
              return { technique: detector.technique, result, vulnerable: !!result?.vulnerable };
            } catch (e) {
              // [P0-FIX 2026-09-09] 区分「检测器报错」的两类语义：
              //   ① 网络层失败（连接被拒/超时/代理不可用）→ 请求没到目标或没回来，
              //      不能记成「已检测、无漏洞」（过去正是这么吞的，是假阴性主因）；
              //   ② 其它异常（payload 构造/解析/断言）→ 该检测器对该点不适用，判负仍可接受。
              const netFail = isNetworkFailureError(e);
              logger.warn(
                `检测器 ${detector.technique} 失败（${netFail ? '网络层，该点结论不可信' : '非网络，按未命中处理'}）：${e.message}`
              );
              return { technique: detector.technique, result: null, vulnerable: false, netFail };
            }
          })
        );
        // 全层皆因网络失败 → 该点「未测成」，记入未决（报告 reliable=false，不再写成安全结论）
        if (inLayer.length > 0 && results.length === inLayer.length && results.every((r) => r.netFail)) {
          if (validityEnabled) validity.addNetworkErrorPoint(point.id);
          point.netErr = true;
          logger.warn(`注入点 ${point.id} 全部检测器因网络层失败退出，标记为未决（不计入阴性结论）`);
        }
        return results.filter((r) => r.vulnerable);
      };

      const found = [];
      // 层1：快速层并行
      const fastHits = await runLayer(FAST);
      found.push(...fastHits);
      const fastConfirmed = fastHits.length > 0;
      // 是否还需跑慢速层：未命中、或 stacked 被选中（需独立确认）→ 跑层2；否则省去慢速层请求
      const needSlow = !fastConfirmed || stackedSelected;
      if (needSlow && !s.cancelled) {
        const slowHits = await runLayer(SLOW);
        found.push(...slowHits);
      }
      if (found.length) foundByPoint.set(point.id, { point, ctx, found });
      // 单点检测+提取完成后落盘（增量持久化，支持断点续拉）。
      // 必须 await：savePointResult 内部是异步写盘，若 fire-and-forget，扫描完成后
      // 写盘可能仍在进行——测试/调用方在扫描结束后清理会话文件会被迟到的写盘重新创建
      // （曾导致 phase3.sessionDefault 测试偶发竞态失败）。
      if (session) await session.savePointResult(point.id, { found: found.map((f) => ({ technique: f.technique, result: f.result })) }).catch(() => null);
      fullyTestedPoints.add(point.id);
    }, 0); // [MERGED: perf] retry=0：单请求重试归 HttpClient 统一负责，避免双重放大为 (retry+1)² 次物理请求

    // 3.4) WAF 自动 tamper 重跑（P1-D5）：识别到高置信 WAF 且用户未显式配置 tamper 时，
    // 对「未命中点」套用 wafRecommend 推荐链重跑快速层（union/error/boolean），受节流控制。
    // 不覆盖用户显式选择；仅在默认配置下自动兜底，提升 WAF 目标召回。
    // [MERGED: engine ★FIX-3] 统一经 shouldAutoRetry 门控（原实现忽略了
    // defaults.wafEvasion.autoRetry=false 的默认开关，WafIdentifier.shouldAutoRetry 成死代码）。
    const wafVendorsPre = [...wafAgg.values()].sort((a, b) => b.confidence - a.confidence);
    // [P1-FIX 2026-09-08] 拦截处置策略：把「识别到 WAF」从前端提示变成有据可依的发包决策。
    // 复用指纹阶段已抓的 baseline（零额外发包）；未配置 scope/未命中拦截页时 action='none'，
    // 行为与历史一致。'unknown' 兜底结论由 blockPolicy 一票否决（不把形态变更交给一个不知是谁的结论）。
    let blockPolicy = { action: 'none', tamperHint: [], backoffMs: null, reason: '未启用策略' };
    try {
      blockPolicy = decideBlockPolicy({
        genericBlock: wafAgg.get(GENERIC_BLOCK_VENDOR) || null,
        namedVendor: wafVendorsPre.find((v) => v.vendor !== GENERIC_BLOCK_VENDOR) || null,
        status: sharedBaseline?.status ?? null,
        headers: sharedBaseline?.headers ?? null,
        config: target.config,
      });
    } catch (e) {
      logger.warn(`拦截策略计算失败（保持当前发包形态）：${e.message}`);
    }
    if (blockPolicy.action !== 'none') {
      logger.info(`[waf-policy] ${blockPolicy.action}：${blockPolicy.reason}`);
      eventBus.emit(scanId, 'waf_block_policy', {
        action: blockPolicy.action,
        backoffMs: blockPolicy.backoffMs,
        tamperHint: blockPolicy.tamperHint,
        reason: blockPolicy.reason,
      });
    }
    const autoRetryEnabled = sm.wafIdentifier.shouldAutoRetry
      ? sm.wafIdentifier.shouldAutoRetry(wafVendorsPre, target.config)
      : wafVendorsPre.some((v) => v.confidence >= 0.8); // 兼容未注入桩的构造
    // [P1-FIX 2026-09-08] 重跑候选选择：
    //  · 保留原「高置信厂商签名」路径；
    //  · 新增：无高置信签名但策略给出 preferTamper（只有通用拦截证据，自建 WAF/CDN 透传规
    //    则很常见）时也采纳——原实现只认 confidence>=0.8，用户即使开了 autoRetry 也永远不触发；
    //  · 两条路径都经 isUntrustedVendor 过滤，'unknown' 不得触发重跑。
    // 总开关仍是 defaults.wafEvasion.autoRetry=false（默认关，零回归）。
    let highConfWaf = null;
    if (autoRetryEnabled) {
      const trusted = wafVendorsPre.filter((v) => !isUntrustedVendor(v.vendor));
      highConfWaf =
        trusted.find((v) => v.confidence >= 0.8) ||
        (blockPolicy.action === 'preferTamper' || blockPolicy.action === 'pause' ? trusted[0] || null : null);
    }
    // [P0-FIX 2026-09-10 实战实测] 拦截证据驱动的重跑（不依赖 WAF 厂商指纹）
    // 背景：真实站点的「基线响应」永远是干净的——只有带 payload 的请求才被拦，所以
    // WafIdentifier 被动识别率天然为 0，条件 `highConfWaf` 永不成立，autoRetry 形同虚设。
    // 实测（e2e/pentest-lab/waf403）：默认/autoRetry/5 组变形链全部 0 检出，而手工套
    // symboliclogical（OR→||、AND→&&）一次命中 boolean。
    // 判据改为「本次扫描实际出现了拦截响应」：blockHits > 0 且仍有未命中点 → 换算子族重跑。
    const validitySnap = validity?.summary?.() || null;
    const blockHits = Number(validitySnap?.counts?.blockHits ?? 0);
    const adaptiveOnBlock = target.config?.wafEvasion?.adaptiveOnBlock !== false;
    // 判据只看「实际拦截次数」：blockPolicy 依赖基线/WAF 识别结果，而真实站点基线干净时
    // blockPolicy.action 恒为 'none'（本次实测靶场即如此），故不能作为触发条件。
    // [P0-FIX 2026-09-10] 用户已显式配置 tamper 链时不自作主张（对齐 blockPolicy 的
    // 「不覆盖人工接管」语义）：否则人工挂链的 A/B 口径会被自适应重跑污染，
    // 实测表现为 off/on 两档互相串味（off 也涨、on 反降）。
    const userTamperConfigured = !!(target.config?.wafEvasion?.tamper?.enabled);
    const blockAdaptive =
      !highConfWaf && adaptiveOnBlock && !userTamperConfigured && blockHits > 0;
    if (blockAdaptive) {
      blockAdaptiveInfo = {
        triggered: true,
        blockHits,
        chains: OPERATOR_SWAP_CHAINS.map((c) => [...c]),
        note: '未识别到 WAF 厂商但出现拦截响应，已用算子替换族重跑未命中点',
      };
      logger.info(
        `[waf-adaptive] 检出 ${blockHits} 次拦截响应但未识别到 WAF 厂商（基线干净属常态）→ 换算子族重跑未命中点`
      );
      eventBus.emit(scanId, 'waf_block_policy', {
        action: 'adaptiveTamper',
        blockHits,
        tamperHint: OPERATOR_SWAP_CHAINS[0],
        reason: '拦截证据驱动：换算子族（OR→|| / AND→&& / =→RLIKE）重跑',
      });
    }
    // [P1-FIX 2026-09-10 实战实测] 关键词「静默过滤」型绕过重跑
    // 删除型过滤规则（自研正则 / 云 WAF 的「strip 关键词」）不返回 403，而是把 payload 里的
    // union/select/and/-- 直接删掉再执行：error 型 payload 仍会报错（命中 error），
    // 但 union/boolean 的真实形态被破坏 → 数据面通道全 miss（实测 bl 场景默认只 error）。
    // 触发条件：已有 error 命中 + 该点 union/boolean 全 miss + 出现过 5xx（证明该点确实真注入）。
    // 动作：套「插入式双写 + 注释符换 #」链重跑快速层（实测 bl：error → error+boolean，830ms → 94ms）。
    const errorOnlyPoints = [...foundByPoint.values()].filter(
      (f) =>
        f.found.some((x) => x.technique === 'error') &&
        !f.found.some((x) => x.technique === 'union' || x.technique === 'boolean')
    );
    // 5xx 计数注意：SQL 语法错误引出的 500 会被守卫归类到 `injection5xx`（含注入特征），
    // 不计入 `serverErr`——只判 serverErr 会漏掉本次过滤场景，故两者都看。
    const fiveXx =
      Number(validitySnap?.counts?.serverErr ?? 0) + Number(validitySnap?.counts?.injection5xx ?? 0);
    const filterAdaptive =
      adaptiveOnBlock &&
      target.config?.wafEvasion?.filterAdaptive === true && // 默认关（见 defaults.js 说明）
      !blockAdaptive &&
      errorOnlyPoints.length > 0 &&
      fiveXx > 0;
    if (filterAdaptive) {
      blockAdaptiveInfo = {
        triggered: true,
        mode: 'filterBypass',
        errorOnlyPoints: errorOnlyPoints.length,
        chains: FILTER_BYPASS_CHAINS.map((c) => [...c]),
        note: 'error 命中但数据面通道全 miss 且存在 5xx：疑关键词被静默过滤，已用插入式双写链重跑',
      };
      logger.info(
        `[filter-adaptive] ${errorOnlyPoints.length} 个点 error 命中但 union/boolean 全 miss（疑关键词被静默删除）→ 套插入式双写链重跑`
      );
      eventBus.emit(scanId, 'waf_block_policy', {
        action: 'filterBypass',
        tamperHint: FILTER_BYPASS_CHAINS[0],
        reason: '静默过滤证据驱动：插入式双写（AND→ANANDD）+ 注释符换 # 重跑',
      });
    }
    // [P0-FIX 2026-09-08] 目标已被判不可达时不再重跑 WAF 规避（对死目标刷整轮请求无意义）
    if ((highConfWaf || blockAdaptive || filterAdaptive) && !s.cancelled && !validity.shouldAbort) {
      const suggestions = sm.wafRecommend(wafVendorsPre);
      // [P0-FIX 2026-09-10] 拦截驱动路径：不看厂商映射表，直接用算子替换候选链
      // （关键词级黑名单改编码/注释无效，换算子才有效，见 wafRecommend.OPERATOR_SWAP_CHAINS）
      if (blockAdaptive) {
        suggestions.length = 0;
        for (const plugins of OPERATOR_SWAP_CHAINS) {
          suggestions.push({ vendor: GENERIC_BLOCK_VENDOR, plugins: [...plugins] });
        }
      }
      // [P1-FIX 2026-09-10] 静默过滤路径：用插入式双写链（非算子替换——关键词是被删而非被拦）
      if (filterAdaptive) {
        suggestions.length = 0;
        for (const plugins of FILTER_BYPASS_CHAINS) {
          suggestions.push({ vendor: GENERIC_BLOCK_VENDOR, plugins: [...plugins] });
        }
      }
      // [P1-FIX 2026-09-08] 只有通用拦截证据（未识别厂商）时 wafRecommend 的 _default 链为空数组，
      // 原实现会静默不重跑（识别到了 WAF 但什也不做）。用 blockPolicy 的推荐链补上（同源判据）。
      if (suggestions.length === 0 && blockPolicy.tamperHint?.length) {
        suggestions.push({ vendor: GENERIC_BLOCK_VENDOR, plugins: [...blockPolicy.tamperHint] });
      }
      // [P1-FIX 2026-09-08] 限流/过载退避：目标回了 Retry-After 还立刻重跑整轮，等于自请封 IP。
      if (blockPolicy.backoffMs > 0) {
        const waitMs = Math.min(30000, blockPolicy.backoffMs);
        logger.info(`[waf-policy] 目标限流，重跑前退避 ${waitMs}ms（Retry-After）`);
        const deadline = Date.now() + waitMs;
        while (Date.now() < deadline && !s.cancelled && !validity.shouldAbort) {
          await new Promise((r) => setTimeout(r, Math.min(200, deadline - Date.now())));
        }
        // [P1 2026-09-09] 容量退避后动态降并发（对标文档「只退一个点边界，不降 ratePerSec」缺口）：
        // 目标刚回过限流/过载，退避结束立刻恢复到原并发等于再次加压。复用 db-guard 的
        // schedulerRef.concurrency=1 模式（不碰令牌桶，零回归面），本轮剩余重跑保持低并发，
        // 避免「退避 → 高并发 → 又退避」的抖动循环。
        if (schedulerRef) {
          schedulerRef.concurrency = 1;
          schedulerRef.baseConcurrency = 1;
          logger.warn(`[waf-policy] 容量退避后并发已降至 1（目标限流/过载，本轮剩余重跑低并发）`);
          eventBus.emit(scanId, 'waf_block_policy', { action: 'slowdown', concurrency: 1 });
        }
      }
      // [P1-FIX 2026-09-05] 链动态验证（从"猜链"到"验链"）：候选链逐条发轻量探针实测是否被拦截，
      // 取首条放行的链；全部被拦则跳过重跑（省掉注定失败的整轮检测请求）。
      // 验证异常 → 保守回退 suggestions[0]（对齐旧行为，验证器故障不削弱重跑）。
      let plugins = null;
      // 过滤路径优先用「error-only 点」做链验证对象（探针行为最贴近重跑目标）
      const verifyPoint = filterAdaptive
        ? errorOnlyPoints[0]?.point
        : pointsToScan.find((p) => !foundByPoint.has(p.id)) || pointsToScan[0];
      if (verifyPoint && suggestions.length) {
        plugins = (await verifyTamperChains({
          httpClient: sm.getScanClient(scanId, target),
          target,
          point: verifyPoint,
          chains: suggestions,
          config: target.config || {},
        }))?.plugins ?? null;
      } else {
        plugins = suggestions[0] && suggestions[0].plugins;
      }
      // [P1-FIX 2026-09-10] 过滤路径不走「验链」结论：chainVerify 的拦截判据含
      // 「响应体缩水至基线 50% 以下 = 软拦截」，而过滤场景下 payload 一旦生效，结果集
      // 本就变空/变短（0 行结果页），必被误判为「仍被拦」→ 全部链判失败 → 跳过重跑。
      // 该路径直接采用首选链（非拦截型场景，验链启发式不适用）。
      if (filterAdaptive && (!plugins || !plugins.length)) {
        plugins = FILTER_BYPASS_CHAINS[0];
        logger.info('[filter-adaptive] 链验证对过滤场景不适用（结果集变空被误判软拦截）→ 直接采用首选链');
      }
      if (plugins && plugins.length) {
        const retryConfig = {
          ...target.config,
          wafEvasion: {
            ...(target.config.wafEvasion || {}),
            tamper: { enabled: true, plugins: [...plugins], intensity: 'medium' },
          },
        };
        const retryCtxBase = { httpClient: sm.getScanClient(scanId, target), config: retryConfig };
        // [P1-FIX 2026-09-10] 静默过滤路径的重跑对象是「error-only 点」——它们已被判为「已命中」，
        // 用「未命中点」筛选会把它们全部排除（这正是首版 filterAdaptive 触发了却零增益的原因）。
        // [P0-FIX 2026-09-10] 拦截驱动重跑的候选必须包含「已命中但快速层技术位不全」的点：
        // 主轮在 CRS 下常见结果是只命中 boolean（union 被 942300 拦），这些点已被判「已命中」
        // → 用「未命中点」筛选会把它们全部排除 → union 面永远补不上（实测 num/blind 卡在 8/10）。
        const fastBitCount = (pid) =>
          ((foundByPoint.get(pid)?.found) || []).filter((f) =>
            ['union', 'error', 'boolean'].includes(f.technique)
          ).length;
        const retryPoints = filterAdaptive
          ? errorOnlyPoints.map((f) => f.point)
          : pointsToScan.filter((p) => !foundByPoint.has(p.id) || fastBitCount(p.id) < 2);
        if (retryPoints.length) {
          logger.info(
            `${highConfWaf ? `WAF 识别（${highConfWaf.vendor}）` : '拦截证据（未识别厂商）'}，自动套 tamper [${plugins.join(',')}] 重跑 ${retryPoints.length} 个未命中点（快速层）`
          );
          await scheduler.run(retryPoints, async (point) => {
            if (s.cancelled) return;
            const rctx = {
              ...retryCtxBase,
              target,
              point,
              dbms: point.dbms || dbms,
              // [P1-FIX 2026-09-10] 与主流程 ctx 对齐：缺 dbmsVersion/scanId/session 会让重跑
              // 走与主轮不同的 payload 筛选与盲注缓存路径（过滤场景曾因此不命中）
              dbmsVersion: point.dbmsVersion || dbmsVersion || null,
              scanId,
              session: session || null,
              extractor: sm.extractor,
              // [P1-1] WAF 重跑携带 baseline，防检测器重复基线请求；
              // [P1-FIX 2026-09-10] 例外：静默过滤路径不携带——该路径下 payload 形态被 tamper
              // 大改（双写+注释符），复用主轮原始基线会让「真值≈基线」判定失配，需检测器自行重采样。
              // [P0-FIX 2026-09-10] 自适应重跑同样不携带主轮 baseline：主轮基线是「未套 tamper」
              // 形态，重跑 payload 套了 tamper 后形态已变，复用会让「真值≈基线」判定失配
              // （实测：携带时 CRS 场景 str/like 重跑 0 命中；不携带时命中 union+boolean）。
              ...(filterAdaptive || blockAdaptive ? {} : { baseline: sharedBaseline }),
            };
            const fast = sm.activeDetectors(retryConfig).filter((d) =>
              ['union', 'error', 'boolean'].includes(d.technique)
            );
            // [P0-FIX 2026-09-10 实战实测] 重跑前重探闭合前缀（boundary）。
            // 根因：主轮的 boundary 探测 payload **不带 tamper**，在 CRS 下被 942460 拦光 →
            // probeBoundary 回退空串 → 重跑时探针变成无闭合形态（`alice AND 1=1#` 落进字符串字面量
            // → 真假双双空结果 → similar=true → 门控失败 → union 恒 0）。
            // 实测证据：gate 插桩 `boundary="" truePayload="alice AND 1=1#" trueLen=138 falseLen=138`。
            // 重跑已带 tamper（`#` 形态可过 CRS），故重探即可拿到正确的 `'`。
            if (blockAdaptive || filterAdaptive) {
              const prober = fast.find((d) => typeof d.probeBoundary === 'function');
              if (prober) {
                try {
                  const b = await prober.probeBoundary({ ...rctx, point });
                  if (typeof b === 'string' && b !== point.boundary) {
                    logger.info(`[waf-adaptive] 重探闭合前缀：${JSON.stringify(point.boundary || '')} → ${JSON.stringify(b)}`);
                    point.boundary = b;
                  }
                } catch (e) {
                  logger.warn(`重探闭合前缀失败（沿用主轮结果）：${e.message}`);
                }
              }
            }
            const results = await Promise.all(
              fast.map(async (detector) => {
                eventBus.emit(scanId, 'point_testing', { pointId: point.id, technique: detector.technique, tamperRetry: true });
                try {
                  const result = await detector.detect(rctx);
                  return { technique: detector.technique, result, vulnerable: !!result?.vulnerable };
                } catch (e) {
                  logger.warn(`WAF 重跑检测器 ${detector.technique} 失败：${e.message}`);
                  return { technique: detector.technique, result: null, vulnerable: false };
                }
              })
            );
            const hits = results.filter((r) => r.vulnerable);
            if (hits.length) {
              // [P1-FIX 2026-09-10] error-only 点重跑：原实现直接 set 会**覆盖**已有的 error 命中，
              // 导致「补了 boolean 却丢了 error」。改为按技术去重合并保留。
              const prev = foundByPoint.get(point.id);
              if (prev) {
                const merged = [...prev.found];
                for (const h of hits) {
                  if (!merged.some((x) => x.technique === h.technique)) merged.push(h);
                }
                foundByPoint.set(point.id, { point, ctx: prev.ctx || rctx, found: merged });
              } else {
                foundByPoint.set(point.id, { point, ctx: rctx, found: hits });
              }
            }
          }, 0); // [MERGED: perf] retry=0：同主循环，单请求重试归 HttpClient
        }
      }
    }

    // 3) 聚合 + 去重（已抽至 scan/aggregate.js，纯搬移）
    const { finalVulns, corroborations } = aggregateVulns({ sm, scanId, foundByPoint });

    // [MERGED: engine ★FIX-1] 用户已 stop()：不再发起任何新的检测/写请求。聚合（纯内存）已完成，
    // 此处直接收尾，保持 status='stopped'。原实现会继续跑二阶段/NoSQL/提取，且最终把 status
    // 覆盖为 'completed'——二阶检测在用户中止后仍会对目标发起真实写请求（POST 注册/评论），
    // 这是安全与一致性的双重问题。
    if (s.cancelled) {
      report.vulns = finalVulns;
      report.summary.stackedEnabled = stackedSelected;
      report.summary.stackedCorroborations = corroborations;
      report.riskLevel = sm.reportGen.riskOf(finalVulns);
      report.dbms = dbms;
      report.finishedAt = new Date().toISOString();
      // [P0-FIX 2026-09-08] stopped 收尾同样要落可信度结论：用户中断 + 目标不可达时的 0 漏洞
      // 必须被标为 inconclusive，而非留成「看起来扫完了」的空报告
      applyValidity(report, { points: pointsToScan, done: fullyTestedPoints });
      if (session) await session.finalize(report).catch(() => {});
      eventBus.emit(scanId, 'scan_stopped_finalized', { scanId, vulns: finalVulns });
      await sm._maybeClose(ctxBase.httpClient);
      sm._retire(scanId);
      return;
    }

    // 3.5) 二阶补充趟 + 3.6) 非 SQL 补充趟（已抽至 scan/supplemental.js，纯搬移）
    await supplementalPasses({ sm, scanId, target, points, dbms, validity, finalVulns });

    // 4) 提取（已抽至 scan/extract.js，纯搬移）
    await extractPhase({ sm, scanId, s, target, foundByPoint, finalVulns, extracted, report });

    // 5) 汇总报告并定级（已抽至 scan/finalize.js，纯搬移）
    await finalizeReport({
      sm, scanId, s, target, report, finalVulns, extracted, restored, session,
      points, pointsToScan, fullyTestedPoints, stackedSelected, corroborations,
      oobUnavailable, dbms, guard, wafAgg, blockPolicy, blockAdaptiveInfo, validity, ctxBase,
      applyValidity, // 闭包函数（scanRunner 内定义），随上下文传入
    });
}

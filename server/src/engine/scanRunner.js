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
// [状态收拢] 暂停轮询/日志节流常量收拢至 scan/constants.js
import { PAUSE_POLL_MS, HTTP_LOG_THROTTLE_MS } from './scan/constants.js';
// [拆分第一批 2026-09-12] runScanLoop 阶段外移（纯搬移，行为不变）
import { supplementalPasses } from './scan/supplemental.js';
import { finalizeReport } from './scan/finalize.js';
import { aggregateVulns } from './scan/aggregate.js';
import { extractPhase } from './scan/extract.js';
import { detectPhase } from './scan/detect.js';
import { discoverPoints } from './scan/discover.js';

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
    // [状态收拢 2026-09-12] 显式运行期上下文：各阶段函数统一接收 run（见 scan/*.js），
    // 阶段产出通过 Object.assign(run, …) 回填，替代原先 37 个散闭包变量的隐式共享
    const run = { sm, scanId, s, target, report };
    // [P0-FIX 2026-09-06] baseUrl 规范化：调用方只给 url 时补齐（real-world-lab verify 等
    // 只传 url 的入口，_crawlForms/_fetchHtml/colGuessScopeKey 等多处依赖 baseUrl，
    // 缺失时表单爬取静默失败 → 二阶存储点为空 → second_order 零检出）
    if (!target.baseUrl && target.url) target.baseUrl = target.url;
    // 按 scanId 注入扫描作用域 HttpClient（独立限速桶，前端 ratePerSec 生效）
    const rawClient = sm.getScanClient(scanId, target);
    run.rawClient = rawClient;
    // [请求日志] 包一层：请求完成后发 http_request 事件（节流 250ms，URL 脱敏）
    // 直连模式（DirectConnector 无 url 语义）跳过；前端 ProgressView 时间线展示
    const client = rawClient && typeof rawClient.request === 'function' ? rawClient : null;
    // [⑮] 扫描级 AbortSignal：stop() 时 abort，中断所有在途 HTTP 请求
    const scanSignal = sm.getSignal ? sm.getSignal(scanId) : null;
    // [熔断] 守卫需早于 ctxBase 创建（ctxBase 被 ctx 与预筛选/指纹共用）；
    // scheduler 在 detect 阶段才构造，故闭包改为延迟读 run.schedulerRef（时序安全）
    const guard = new DbHealthGuard({
      onTrip: ({ id, hint }) => {
        // 同步压住基准并发，避免 _maybeAdjust 在延迟回落时把并发又抬回原值
        const sc = run.schedulerRef;
        if (sc) {
          sc.concurrency = 1;
          sc.baseConcurrency = 1;
        }
        logger.error(`[db-guard] 目标数据库报致命错误（${id}），并发已降至 1 并停止重型 payload：${hint}`);
        eventBus.emit(scanId, 'db_health_tripped', { id, hint, concurrency: 1 });
      },
    });
    run.guard = guard;
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
    run.validity = validity;
    run.validityEnabled = validityEnabled;
    run.observeValidity = observeValidity;
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
    run.applyValidity = applyValidity;

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
    run.ctxBase = ctxBase;

    const cfg = target.config || {}; // [拆分3a] 上移：阶段 2/3.4 与 discover 共用
    run.cfg = cfg;
    // 1) 发现注入点 + 点位准备（已抽至 scan/discover.js，纯搬移）
    Object.assign(run, await discoverPoints(run));
    // 解构为本函数局部名（后续代码保持原可读性；pointsToScan/session 下游只读）
    const { points, pointsToScan, session, restored } = run;

    // 2) 调度检测 + 3.4) WAF 自适应重跑（已封边至 scan/detect.js，纯搬移）
    Object.assign(run, await detectPhase(run));
    const { foundByPoint, extracted, dbms, blockPolicy, blockAdaptiveInfo, stackedSelected, fullyTestedPoints, oobUnavailable, wafAgg } = run;
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

// =====================================================================
// supplementalRuns.js — 补充检测趟：二阶注入（_runSecondOrder，存储组并行 + 组内串行）
// 与非 SQL 注入（_runNoSql，点并行 + 类别串行），均 opt-in、对一阶零侵入。
// [2026-10-01 自 ScanManager.js 拆出（纯搬移）]：由 ScanManager.prototype 挂载（this 语义不变）。
// 注意：与已有的 scan/supplemental.js（scanRunner 的 supplementalPasses 编排器）是两回事。
// =====================================================================
import * as eventBus from '../../core/eventBus.js';
import { logger } from '../../core/logger.js';
import { oobReceiver } from '../../core/oobReceiver.js';
import { createVulnerability } from '../models.js';

  // 二阶注入补充趟：在既有一阶聚合之后运行，对"每个存储点 × 每个触发页"调用独立 SecondOrderDetector。
  // 门控（唯一硬门）：secondOrder.enabled && triggerUrls 非空 && 存在 isStorePoint 点；
  // 否则直接 return []（零写、对一阶零侵入）。命中结果复用既有 foundByPoint → 聚合去重 → riskOf 通道。
export async function _runSecondOrder(scanId, target, points, dbms) {
    const so = (target.config && target.config.secondOrder) || {};
    if (!so.enabled) return []; // 未启用：直接跳过，对目标零写
    const triggerUrls = Array.isArray(so.triggerUrls) ? so.triggerUrls : [];
    if (triggerUrls.length === 0) return []; // 无候选触发页：跳过
    const storePoints = points.filter((p) => p && p.isStorePoint);
    if (storePoints.length === 0) return []; // 无存储点：跳过

    // 告警：开启二阶检测即代表将对目标发起真实写请求（POST 注册/评论/资料）
    logger.warn(
      '二阶检测已开启：将对目标发起真实写请求（POST 注册/评论/资料），仅在你确认已授权目标时执行'
    );

    // 二阶 OOB 触发：oobTrigger 开启且 oob 启用时，确保带外接收端就绪（幂等；失败仅告警不阻断，
    // 检测器侧会再以 OOB_DISABLED 拒绝未就绪分支，由下方 try/catch 捕获记录）
    const oobCfg = (target.config && target.config.oob) || {};
    if (so.oobTrigger === true && oobCfg.enabled) {
      try {
        await oobReceiver.start(oobCfg);
      } catch (e) {
        logger.warn(`二阶 OOB 接收端启动失败，OOB 触发判定将不可用：${e.message}`);
      }
    }

    const collected = [];
    // [P0-FIX 2026-09-06] ctxBase 补 dbms：缺失时 SecondOrderDetector._buildProbe 走
    // SECOND_ORDER_PROBES[0]（单引号裸探针）而非该库报错模板 → 探针退化必漏（real-world-lab 实测）
    const ctxBase = { httpClient: this._wrapWithSignal(scanId, this.getScanClient(scanId, target)), config: target.config, dbms };
    // [P1-FIX 2026-09-07] 按「存储目标」分组调度：同一 actionUrl（同一张表单）的字段共享
    // 同一份存储——并发检测时 A 点刚写入的探针会被 B 点的写入覆盖（实测 body 点探针被
    // item_id 点阴性对照覆盖 → 触发页读到良性值 → 恒漏检）。故同组内严格串行，
    // 不同 actionUrl（不同表单/不同存储）之间仍可并行。
    const storeGroups = new Map();
    for (const p of storePoints) {
      const key = String(p.actionUrl || p.id);
      if (!storeGroups.has(key)) storeGroups.set(key, []);
      storeGroups.get(key).push(p);
    }
    const groups = [...storeGroups.values()];
    // [MERGED: perf] 并发治理：旧实现双层 for 全串行（storePoints × triggerUrls 逐对 await），
    // 10 存储点 × 3 触发页 = 30 次检测墙钟线性累加。现按「存储组」并行（_mapPool 限并发，
    // 默认 2；组内存储点与触发页均串行——同一存储内并发写会相互污染读回判定）。
    const concurrency = Math.max(1, Math.min(Number(so.concurrency) || 2, groups.length));
    await this._mapPool(
      groups,
      async (group) => {
        for (const point of group) {
          const pointDbms = dbms || point.dbms; // 复用一阶已识别的 dbms（若有时）
          for (const triggerUrl of triggerUrls) {
            const ctx = { ...ctxBase, target, point, dbms: pointDbms, triggerUrl, scanId };
            try {
              const result = await this.secondOrderDetector.detect(ctx);
              if (result.vulnerable) {
                // 复用既有聚合/风险纳管通道：先经 ReportGenerator.riskOf 定级（second_order → High）
                const risk = this.reportGen.riskOf([
                  createVulnerability(point.id, 'second_order', 'Medium', result.payloads, result.evidence),
                ]);
                const vuln = createVulnerability(
                  point.id,
                  'second_order',
                  risk,
                  result.payloads,
                  result.evidence
                );
                vuln.dbms = result.dbms;
                collected.push(vuln);
                eventBus.emit(scanId, 'detection_found', { ...result, riskLevel: risk });
              }
            } catch (e) {
              logger.warn(`二阶检测失败（点 ${point.id} / 触发页 ${triggerUrl}）：${e.message}`);
            }
          }
        }
      },
      concurrency
    );
    await this._maybeClose(ctxBase.httpClient);
    return collected;
  }

  // 非 SQL 注入补充趟（NoSQL/GraphQL/SSTI）：门控 noSql.enabled 才运行，默认关闭（opt-in）。
  // 对一阶流水线零侵入：仅在启用时对每个注入点 × 每个类别（nosql/graphql/ssti）调用独立 NoSqlInjectionDetector。
  // 命中复用既有聚合/风险纳管通道（technique 统一记为 'nosql'，报告层按 noSqlKind 细分展示）。
export async function _runNoSql(scanId, target, points, dbms) {
    const noSql = (target.config && target.config.noSql) || {};
    if (!noSql.enabled) return []; // 未启用：直接跳过，对目标零额外请求
    const kinds = Array.isArray(noSql.kinds) && noSql.kinds.length ? noSql.kinds : ['nosql', 'graphql', 'ssti'];
    const collected = [];
    const ctxBase = { httpClient: this._wrapWithSignal(scanId, this.getScanClient(scanId, target)), config: target.config };
    logger.info(`非SQL注入检测已开启（类别：${kinds.join('/')}），将对 ${points.length} 个注入点逐一探测`);
    // [MERGED: perf] 并发治理：旧实现点 × 类别双层串行；现按「注入点」并行（_mapPool 限并发 2），
    // 同一注入点内类别仍串行（探测表按成本升序命中即停的短路语义不变）。
    const concurrency = Math.max(1, Math.min(Number(noSql.concurrency) || 2, points.length));
    await this._mapPool(
      points,
      async (point) => {
        for (const kind of kinds) {
          const ctx = { ...ctxBase, target, point, dbms: dbms || point.dbms, noSqlKind: kind };
          try {
            const result = await this.noSqlDetector.detect(ctx);
            if (result.vulnerable) {
              const risk = this.reportGen.riskOf([
                createVulnerability(point.id, 'nosql', 'Medium', result.payloads, result.evidence),
              ]);
              const vuln = createVulnerability(point.id, 'nosql', risk, result.payloads, result.evidence);
              vuln.dbms = null;
              vuln.noSqlKind = kind; // 透传细分类别（NoSQL/GraphQL/SSTI）
              collected.push(vuln);
              eventBus.emit(scanId, 'detection_found', { ...result, riskLevel: risk });
            }
          } catch (e) {
            logger.warn(`非SQL注入检测失败（点 ${point.id} / 类别 ${kind}）：${e.message}`);
          }
        }
      },
      concurrency
    );
    await this._maybeClose(ctxBase.httpClient);
    return collected;
  }

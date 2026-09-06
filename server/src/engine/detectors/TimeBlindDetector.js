import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload, getClauseTemplates } from '../payloads.js';
import { selectPayloads } from '../payloadRegistry.js';
import { defaults } from '../../config/defaults.js';
import { mean, std, effectiveThreshold, adaptiveTimeFloor } from '../../core/statsHelper.js';

// 时间盲注检测器
// 思路：注入 SLEEP/pg_sleep/WAITFOR 等延迟 Payload，比对响应耗时是否 ≥ 阈值且稳定多次
// 时间向量定库候选序（dbms 未知时按常见度遍历）：各库 sleep 函数差异即「时间指纹」
// [⑯] 补全 ClickHouse/Sybase（SUPPORTED 标 time:true 且有 PAYLOADS.time 模板）
// [P1] 补全 H2/MonetDB（SLEEP(ms) / sys.sleep(sec)）
const TIME_DBMS_ORDER = ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite', 'ClickHouse', 'Sybase', 'H2', 'MonetDB'];

export class TimeBlindDetector extends Detector {
  constructor() {
    super('time');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { dbms } = ctx;
    // T1 响应匹配多指标：用户显式配置时，时间盲注也复用「基线 vs 注入响应」匹配指标作为补充判定；
    // 命中即返回，未命中回落常规时间判定（默认未配置，路径不变）。
    if (this.hasExplicitMatch(ctx.config)) {
      const metricResult = await this._detectMatchMetrics(ctx, dbms);
      if (metricResult.vulnerable) return metricResult;
    }
    // dbms 已知：直接用该库时间模板
    if (dbms && PAYLOADS[dbms] && PAYLOADS[dbms].time) {
      const r = await this._detectOne(ctx, dbms);
      // 扩展轮（对标 sqlmap --level）：主模板未命中且 level>=2 时，追加更多 time 变体
      // （括号闭合 / 函数变体 / ORDER BY 子句位置延迟），有界 2-4 条；level=1 不投放。
      if (!r.vulnerable && Number(ctx.config && ctx.config.level) >= 2) {
        return this._extendedRound(ctx, dbms, r);
      }
      return r;
    }
    // dbms 未知：时间向量定库两段式（[P1-FIX 2026-09-05] 降本，判定语义不变）：
    //   第一段（粗筛）：每候选库仅发 1 条 sleep 探针（串行，避免 sleep 互相污染），
    //     耗时 ≥ sleep·0.7 判定候选存活（sleep 主导阈值：执行了 sleep 的响应必然 ≥ sleep 秒）。
    //   第二段（确认）：粗筛通过的候选按常见度序跑全量 _detectOne（robust μ+zσ 检验），命中即定库。
    // 成本：负路径（无注入）90 请求 → ~19；正路径第 k 位候选命中 k×10 → ~k+10。
    // 原实现的循环后 MySQL 兜底重跑全量属冗余（MySQL 已是首个候选），保留兜底语义但
    // 仅在 MySQL 粗筛未通过时触达（此时全量跑一次与历史行为一致，换取零回归）。
    let mysqlFallback = null;
    for (const candidate of TIME_DBMS_ORDER) {
      if (!(await this._coarseProbe(ctx, candidate))) continue;
      const r = await this._detectOne(ctx, candidate);
      if (r.vulnerable) return r;
      if (candidate === 'MySQL') mysqlFallback = r;
    }
    if (mysqlFallback) return mysqlFallback;
    return this._detectOne(ctx, 'MySQL');
  }

  // 粗筛探针：单条 sleep 请求（串行），sleep 主导阈值判定候选库时间向量是否存活。
  // 仅用于 dbms 未知时的定库粗筛，不参与最终判定（确认走 _detectOne 的 robust 统计检验）。
  async _coarseProbe(ctx, dbms) {
    const templates = this._resolveTimeTemplates(ctx, dbms);
    if (!templates || !templates.length) return false;
    const { httpClient, target, point } = ctx;
    const orig = point.originalValue || '1';
    const sleep = this._probeSleep(ctx);
    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig: `${orig}${point.boundary || ''}`, sleep }));
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000 + 2000;
    try {
      const start = Date.now();
      const res = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), { timeoutMs });
      const elapsed = (Date.now() - start) / 1000;
      return !!(res && elapsed >= sleep * 0.7);
    } catch {
      return false;
    }
  }

  // 单一库检测（legacy/robust 双路径复用）
  async _detectOne(ctx, dbms) {
    const templates = this._resolveTimeTemplates(ctx, dbms);
    const result = createDetectionResult(ctx.point.id, 'time');
    if (!templates || !templates.length) return result;
    // 覆盖 ctx.dbms，使 legacy/robust 内部解构拿到正确库（避免写 point.dbms 为 null）
    const ctxDbms = { ...ctx, dbms };
    const rb = ctx.config?.blindRobust;
    if (!rb || rb.enabled === false) {
      return this._legacyDetect(ctxDbms, result, templates);
    }
    return this._robustDetect(ctxDbms, result, templates, rb);
  }

  /**
   * 时间向量模板解析（声明式注册表默认路径）。
   * 默认 true：使用 selectPayloads() 按 level/risk/dbms/testFilter/testSkip 筛选
   * 声明式注册表条目（对标 sqlmap level/risk/dbms + --test-filter/--test-skip 过滤语义），
   * 返回其 template 字段数组。
   * config.useRegistry === false 时回退 PAYLOADS[dbms].time 扁平数组（向后兼容）。
   *
   * 注册表未覆盖的 DBMS（ClickHouse/Sybase/H2/MonetDB 等仅有 PAYLOADS）自动回退 legacy 路径，
   * 保证零回归。
   *
   * {ORIG} 占位符不在本方法替换 — 由下游 _legacyDetect / _robustDetect 经 fillPayload() 填充。
   *
   * @param {object} ctx { config }
   * @param {string} dbms
   * @returns {string[]}
   */
  _resolveTimeTemplates(ctx, dbms) {
    const cfg = ctx.config || {};
    if (cfg.useRegistry !== false) {
      const level = Number(cfg.level) > 0 ? Number(cfg.level) : undefined;
      const risk = Number(cfg.risk) > 0 ? Number(cfg.risk) : undefined;
      const testFilter = cfg.testFilter || undefined;
      const testSkip = cfg.testSkip || undefined;
      const entries = selectPayloads({ dbms, technique: 'time', level, risk, testFilter, testSkip });
      if (entries.length > 0) {
        return entries.map((p) => p.template);
      }
      // 注册表无该 dbms 的 time 条目（ClickHouse/Sybase/H2/MonetDB 等）→ 回退 legacy 路径
    }
    return PAYLOADS[dbms] && PAYLOADS[dbms].time;
  }

  // 探测阶段 sleep（P2-P8）：timeProbeSleepSec 显式配置时用较短时长（如 1s）压低检测墙钟；
  // 未配置回退 timeBlindSleepSec（与现状一致，零回归）。提取阶段用 timeExtractSleepSec（见 Extractor）。
  _probeSleep(ctx) {
    return ctx.config?.timeProbeSleepSec ?? ctx.config?.timeBlindSleepSec ?? defaults.timeBlindSleepSec ?? 2;
  }

  // —— 响应匹配多指标补充判定：基线(orig) vs 注入(时间 payload) 响应经 matchMetrics 比对 ——
  async _detectMatchMetrics(ctx, dbms) {
    const templates = PAYLOADS[dbms] && PAYLOADS[dbms].time;
    const result = createDetectionResult(ctx.point.id, 'time');
    if (!templates || !templates.length) return result;
    const { httpClient, target, point } = ctx;
    const orig = point.originalValue || '1';
    const sleep = this._probeSleep(ctx);
    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig: `${orig}${point.boundary || ''}`, sleep }));
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;
    const baseRes = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
    const injectRes = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), { timeoutMs });
    const signal = this.matchMetrics(baseRes, injectRes, ctx.config);
    if (signal === true) {
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `时间盲注确认(响应匹配多指标): 基线/注入响应命中显式匹配指标（${this._metricLabels(ctx.config)}）`;
      result.payloads = [payload];
      point.confirmed = true;
      point.technique = 'time';
      point.dbms = dbms;
    }
    return result;
  }

  // —— 现状逻辑（原样保留，不重构）——
  async _legacyDetect(ctx, result, templates) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    // 触发明显延迟（秒）：P2-P5 支持 config.timeBlindSleepSec 配置；P2-P8 优先 timeProbeSleepSec
    // （探测阶段较短时长压低墙钟，如 1s），未配置回退 timeBlindSleepSec（默认 2，与历史行为一致）
    const sleep = this._probeSleep(ctx);
    const threshold = (ctx.config?.timeThresholdMs ?? defaults.timeThresholdMs) / 1000;
    // [主代理收尾] 采样数读 config（此前硬读 defaults，REST 透传的 timeBlindSamples 不生效）；
    // clamp [1,10]（与 sanitizeStart 白名单区间兼容，防直连引擎传病态值）
    const samples = Math.min(10, Math.max(1, ctx.config?.timeBlindSamples ?? defaults.timeBlindSamples));

    // boundary 感知：探测到闭合前缀时，用「闭合前缀 + 延迟 payload + 注释」
    const payload = this.obfuscateValue(
      ctx,
      fillPayload(templates[0], { orig: `${orig}${point.boundary || ''}`, sleep })
    );
    // 放宽超时，避免把正常延迟误判为超时
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;

    // 基线：先测目标正常响应用时，避免把本身就慢的目标误判为时间盲注
    let baseSum = 0;
    let baseN = 0;
    for (let i = 0; i < samples; i++) {
      const s0 = Date.now();
      try {
        await this.send(httpClient, ctx, this.buildRequest(target, point, orig), {});
      } catch {
        /* 忽略基线探测误差 */
      }
      baseSum += (Date.now() - s0) / 1000;
      baseN++;
    }
    const baseMean = baseN ? baseSum / baseN : 0;

    // 判定：注入后耗时须明显超过「基线 + 阈值」且多次稳定，否则视为目标本就慢
    let stable = 0;
    for (let i = 0; i < samples; i++) {
      const start = Date.now();
      let res = null;
      try {
        res = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), {
          timeoutMs,
        });
      } catch {
        // 超时或网络错误，视为未触发延迟
        continue;
      }
      const elapsed = (Date.now() - start) / 1000;
      if (res && elapsed >= baseMean + threshold) stable++;
    }

    if (stable >= Math.ceil(samples / 2)) {
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `时间盲注确认：连续 ${stable}/${samples} 次延迟 ≥ 基线(${baseMean.toFixed(2)}s)+${threshold.toFixed(1)}s`;
      result.payloads = [payload];
      point.confirmed = true;
      point.technique = 'time';
      point.dbms = dbms;
    }
    return result;
  }

  // —— 鲁棒分支：基线分布感知（μ + z·σ）阈值 + 稳定率判定（抗抖动/慢目标）——
  // 基线与注入采样均改为限并发（sendConcurrent），抵消串行开销；baseline 样本补 excerpt 片段。
  async _robustDetect(ctx, result, templates, rb) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    // P2-P5/P2-P8：sleep 可配置（timeProbeSleepSec 优先，探测阶段较短；未配置回退 timeBlindSleepSec=2）
    const sleep = this._probeSleep(ctx);
    const absFloor = (ctx.config?.timeThresholdMs ?? defaults.timeThresholdMs) / 1000;
    const concurrency = rb.concurrency || 4;

    // 1) 基线分布（μ, σ）——并发采样
    const baselineReqs = [];
    for (let i = 0; i < rb.baselineSamples; i++) baselineReqs.push(this.buildRequest(target, point, orig));
    const baselineResps = await this.sendConcurrent(httpClient, ctx, baselineReqs, {}, concurrency);
    const baselineElapsed = baselineResps.map((r) => ((r.__elapsed || 0) / 1000));
    const baselineExcerpts = baselineResps.map((r) => this._excerptOf(r));
    const mu = mean(baselineElapsed);
    const sigma = std(baselineElapsed);

    // 2) 分布感知阈值：μ + z·σ 为主，叠加自适应绝对下限（σ=0 退化为 μ+absFloor ≡ legacy 固定阈值）。
    //    自适应下限 = absFloor + scale·σ：稳定目标(σ≈0)与现状一致；抖动目标(σ 大)下限更宽，抑制微抖动误报。
    const floor = rb.adaptive ? adaptiveTimeFloor(absFloor, sigma, rb.adaptiveTimeFloorScale) : absFloor;
    const threshold = Math.max(effectiveThreshold(mu, sigma, rb.timeConfidenceZ, absFloor), mu + floor);

    // [--time-sec 自适应] 标定探针（对标 sqlmap 先测基线延迟再选 sleep 秒数）
    // 仅在 config.timeBlindCalibrate=true 时生效，默认 false 零回归
    const cfg = ctx.config || {};
    const calibrate = cfg.timeBlindCalibrate === true;
    const calibrateMin = Math.max(0.5, Number(cfg.timeBlindCalibrateMin) || 1);
    let effectiveSleep = sleep;
    if (calibrate && calibrateMin < sleep) {
      const probePayload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig: `${orig}${point.boundary || ''}`, sleep: calibrateMin }));
      const probeTimeout = (cfg.timeoutMs || 5000) + calibrateMin * 1000;
      try {
        const t0 = Date.now();
        await this.send(httpClient, ctx, this.buildRequest(target, point, probePayload), { timeoutMs: probeTimeout });
        const elapsed = Date.now() - t0;
        // 探针耗时 ≥ 判定阈值 → 标定成功，用短 sleep
        if (elapsed >= (cfg.timeThresholdMs || 5000)) {
          effectiveSleep = calibrateMin;
        }
      } catch { /* 探针失败 → 保持原 sleep */ }
    }

    // boundary 感知：闭合前缀拼进 orig，修复括号/引号包裹场景的时间盲注漏检
    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig: `${orig}${point.boundary || ''}`, sleep: effectiveSleep }));
    // 放宽超时，避免把正常延迟误判为超时
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + effectiveSleep * 1000;

    // 3) 注入采样 + 稳定率判定（采样次数读 config.timeBlindSamples，[主代理收尾] 修复此前
    //    硬读 defaults 导致 REST 透传不生效的配置语义漂移；clamp [1,10] 与白名单区间一致）
    const samples = Math.min(10, Math.max(1, ctx.config?.timeBlindSamples ?? defaults.timeBlindSamples));
    const injectReqs = [];
    for (let i = 0; i < samples; i++) injectReqs.push(this.buildRequest(target, point, payload));
    const injectResps = await this.sendConcurrent(httpClient, ctx, injectReqs, { timeoutMs }, concurrency);
    const injectSamples = [];
    let stableHits = 0;
    for (let i = 0; i < samples; i++) {
      const r = injectResps[i];
      const elapsed = (r.__elapsed || 0) / 1000;
      const delayed = !r.__error && r.resp != null && elapsed >= threshold;
      injectSamples.push({ idx: i, ms: Math.round(elapsed * 1000) / 1000, delayed, excerpt: r.__error ? '' : this._excerptOf(r) });
      if (delayed) stableHits++;
    }
    const stableRatio = stableHits / samples;

    if (stableRatio >= rb.minStableRatio) {
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `时间盲注确认(统计${rb.adaptive ? '·自适应' : ''}): μ=${mu.toFixed(2)}s σ=${sigma.toFixed(2)}s z=${rb.timeConfidenceZ} 阈值=${threshold.toFixed(2)}s 自适应下限=${floor.toFixed(2)}s 稳定率${stableRatio.toFixed(2)}`;
      result.payloads = [payload];
      point.confirmed = true;
      point.technique = 'time';
      point.dbms = dbms;
    }
    // 结构化轨迹（命中/未命中均透传，供前端时间线可视化）
    result.trace = {
      technique: 'time',
      adaptive: !!rb.adaptive,
      baselineNoiseRate: null,
      mu,
      sigma,
      threshold,
      floor,
      baselineSamples: baselineResps.map((r, i) => ({ idx: i, ms: Math.round(baselineElapsed[i] * 1000) / 1000, excerpt: baselineExcerpts[i] })),
      injectSamples,
      stableRatio,
      decision: result.vulnerable ? 'vulnerable' : 'clean',
    };
    return result;
  }

  // 从 sendConcurrent 返回元素安全取响应体片段（并发失败降级空串）
  _excerptOf(r) {
    if (!r || r.__error || !r.resp) return '';
    return String(r.resp?.data ?? '').slice(0, 160);
  }

  // —— 扩展轮（level>=2 门控）：主模板（templates[0]）未命中时追加变体 ——
  // 候选有界：主 time 模板 [1..2] + 子句位置 time 变体（ORDER BY 逗号拼接延迟）≤2，共 ≤4 条；
  // 判定与 legacy 同构：基线均值 + 阈值，连续 ≥ 半数采样延迟即确认（采样 3 次，控请求量）。
  async _extendedRound(ctx, dbms, result) {
    const { httpClient, target, point } = ctx;
    const orig = point.originalValue || '1';
    const sleep = this._probeSleep(ctx);
    const threshold = (ctx.config?.timeThresholdMs ?? defaults.timeThresholdMs) / 1000;
    const tpls = [
      ...(PAYLOADS[dbms]?.time || []).slice(1, 3),
      ...getClauseTemplates(dbms, 'time', { maxPerClause: 2, maxTotal: 2 }).map((t) => t.tpl),
    ];
    if (!tpls.length) return result;

    // 基线 3 次取均值（与 legacy 同思路，压低扩展轮成本）
    let baseSum = 0;
    let baseN = 0;
    for (let i = 0; i < 3; i++) {
      const s0 = Date.now();
      try {
        await this.send(httpClient, ctx, this.buildRequest(target, point, orig), {});
      } catch {
        /* 忽略基线探测误差 */
      }
      baseSum += (Date.now() - s0) / 1000;
      baseN++;
    }
    const baseMean = baseN ? baseSum / baseN : 0;
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;
    const samples = 3;

    for (const tpl of tpls) {
      const payload = this.obfuscateValue(
        ctx,
        fillPayload(tpl, { orig: `${orig}${point.boundary || ''}`, sleep })
      );
      let stable = 0;
      for (let i = 0; i < samples; i++) {
        const start = Date.now();
        let res = null;
        try {
          res = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), { timeoutMs });
        } catch {
          // 超时或网络错误，视为未触发延迟
          continue;
        }
        if (res && (Date.now() - start) / 1000 >= baseMean + threshold) stable++;
      }
      if (stable >= Math.ceil(samples / 2)) {
        result.vulnerable = true;
        result.dbms = dbms;
        result.evidence = `时间盲注确认(扩展轮·level≥2): 变体连续 ${stable}/${samples} 次延迟 ≥ 基线(${baseMean.toFixed(2)}s)+${threshold.toFixed(1)}s`;
        result.payloads = [payload];
        point.confirmed = true;
        point.technique = 'time';
        point.dbms = dbms;
        if (result.trace) result.trace.decision = 'vulnerable';
        return result;
      }
    }
    return result;
  }
}

export default TimeBlindDetector;

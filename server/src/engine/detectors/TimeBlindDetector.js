import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload } from '../payloads.js';
import { defaults } from '../../config/defaults.js';
import { mean, std, effectiveThreshold, adaptiveTimeFloor } from '../../core/statsHelper.js';
import { normalizeDetectMatch, evaluateDetectMatch } from '../detectionMatch.js';

// 时间盲注检测器
// 思路：注入 SLEEP/pg_sleep/WAITFOR 等延迟 Payload，比对响应耗时是否 ≥ 阈值且稳定多次
export class TimeBlindDetector extends Detector {
  constructor() {
    super('time');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'time');
    const templates = (PAYLOADS[dbms] && PAYLOADS[dbms].time) || PAYLOADS.MySQL.time;

    // 时间盲注 SLEEP 触发时长（对标 sqlmap --time-sec）。默认 2s 保零回归。
    const sleep = this._sleepFor(ctx);

    // 自定义检测锚点（--string/--not-string/--regexp/--code）：确定性短路，覆盖统计判定分支。
    // 时间场景以「延迟 payload 响应」为真、「正常 orig 响应」为假，按内容/状态码比对。
    const match = normalizeDetectMatch(ctx.config);
    if (match) {
      return this._detectWithMatch(ctx, result, templates, match, sleep);
    }


    // 双路径：blindRobust 未启用（或未配置）时走现状 legacy 逻辑，确保零回归
    const rb = ctx.config?.blindRobust;
    if (!rb || rb.enabled === false) {
      return this._legacyDetect(ctx, result, templates, sleep);
    }
    return this._robustDetect(ctx, result, templates, rb, sleep);
  }

  // —— 相对 SLEEP 派生的"绝对下限"（秒）——
  // 设计要点：阈值绝对下限必须随 SLEEP 时长走，否则低 --time-sec（如 1s）会让"延迟判定门槛"
  // 高于实际触发延迟 → 假阴性。默认 sleep=2 → 下限 1.5s，与改造前 timeThresholdMs=1500 逐字节一致。
  _absFloorFor(sleep) {
    return Math.max(0.3, sleep - 0.5);
  }

  // 取本次时间盲注的 SLEEP 时长（秒），默认 2 保零回归。
  _sleepFor(ctx) {
    const s = ctx.config?.timeSec;
    if (typeof s === 'number' && s >= 1) return Math.min(100, s); // 上限 100s 防失控
    return defaults.timeSec;
  }

  // —— 自定义锚点确定性判定（--string/--not-string/--regexp/--code）——
  // 时间场景：延迟 payload 响应为真、正常 orig 响应为假，按内容/状态码比对（AND 通过即判漏洞）。
  async _detectWithMatch(ctx, result, templates, match, sleep) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig, sleep }));
    // 放宽超时，避免把正常延迟误判为超时
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;

    const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), { timeoutMs });
    const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
    const trueBody = String(rTrue?.data ?? '');
    const falseBody = String(rFalse?.data ?? '');
    const trueStatus = typeof rTrue?.status === 'number' ? rTrue.status : 0;
    const falseStatus = typeof rFalse?.status === 'number' ? rFalse.status : 0;

    const { vulnerable, evidence } = evaluateDetectMatch(match, {
      trueBody,
      falseBody,
      trueStatus,
      falseStatus,
    });

    if (vulnerable) {
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `时间盲注确认(自定义锚点): ${evidence}`;
      result.payloads = [payload];
      point.confirmed = true;
      point.technique = 'time';
      point.dbms = dbms;
      result.trace = { technique: 'time', mode: 'detectMatch', decision: 'vulnerable', evidence };
    } else {
      result.evidence = `自定义锚点未命中: ${evidence}`;
      result.trace = { technique: 'time', mode: 'detectMatch', decision: 'clean', evidence };
    }
    return result;
  }

  // —— 现状逻辑（原样保留，不重构）——
  async _legacyDetect(ctx, result, templates, sleep) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    // 绝对下限随 SLEEP 派生：sleep=2 → 1.5s，与改造前 timeThresholdMs=1500 一致
    const threshold = this._absFloorFor(sleep);
    const samples = defaults.timeBlindSamples;

    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig, sleep }));
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
  async _robustDetect(ctx, result, templates, rb, sleep) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    // 绝对下限随 SLEEP 派生：sleep=2 → 1.5s，与改造前 timeThresholdMs=1500 一致
    const absFloor = this._absFloorFor(sleep);
    const payload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig, sleep }));
    // 放宽超时，避免把正常延迟误判为超时
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;
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

    // 3) 注入采样 + 稳定率判定（采样次数复用 timeBlindSamples=3），并记录每次采样轨迹
    const samples = defaults.timeBlindSamples;
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
}

export default TimeBlindDetector;

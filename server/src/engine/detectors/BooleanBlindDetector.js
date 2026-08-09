import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload } from '../payloads.js';
import { similarityRate, twoProportionZ, isSignificant, baselineNoiseRate, adaptiveMinStable } from '../../core/statsHelper.js';
import { normalizeDetectMatch, evaluateDetectMatch } from '../detectionMatch.js';

// 布尔盲注检测器
// 思路：构造真假条件（AND 1=1 / AND 1=2），比对两次响应差异判定注入
export class BooleanBlindDetector extends Detector {
  constructor() {
    super('boolean');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'boolean');
    const templates = (PAYLOADS[dbms] && PAYLOADS[dbms].boolean) || PAYLOADS.MySQL.boolean;

    // 自定义检测锚点（--string/--not-string/--regexp/--code）：确定性短路，覆盖统计判定分支。
    // 仅当 config.detectMatch 含有效锚点时激活；否则走原 legacy/robust 统计路径（零回归）。
    const match = normalizeDetectMatch(ctx.config);
    if (match) {
      return this._detectWithMatch(ctx, result, templates, match);
    }


    // 双路径：blindRobust 未启用（或未配置）时走现状 legacy 逻辑，确保零回归
    const rb = ctx.config?.blindRobust;
    if (!rb || rb.enabled === false) {
      return this._legacyDetect(ctx, result, templates);
    }
    return this._robustDetect(ctx, result, templates, rb);
  }

  // —— 自定义锚点确定性判定（--string/--not-string/--regexp/--code）——
  // 与统计分支正交：发送真假条件各一次，按锚点内容/状态码比对，所有锚点 AND 通过即判漏洞。
  async _detectWithMatch(ctx, result, templates, match) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    const truePayload = this.obfuscateValue(ctx, fillPayload(templates[0], { orig }));
    const falsePayload = this.obfuscateValue(ctx, fillPayload(templates[2], { orig }));

    const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
    const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
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
      result.evidence = `布尔注入确认(自定义锚点): ${evidence}`;
      result.payloads = [truePayload, falsePayload];
      point.confirmed = true;
      point.technique = 'boolean';
      point.dbms = dbms;
      result.trace = { technique: 'boolean', mode: 'detectMatch', decision: 'vulnerable', evidence };
    } else {
      result.evidence = `自定义锚点未命中: ${evidence}`;
      result.trace = { technique: 'boolean', mode: 'detectMatch', decision: 'clean', evidence };
    }
    return result;
  }

  // —— 现状逻辑（原样保留，不重构）——
  async _legacyDetect(ctx, result, templates) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';

    // 基线：采样正常响应用于区分「页面自身动态内容」与「注入导致的差异」
    const baselines = [];
    for (let i = 0; i < 2; i++) {
      const r = await this.send(
        httpClient,
        ctx,
        this.buildRequest(target, point, orig),
        ctx
      );
      baselines.push(String(r?.data ?? ''));
    }

    // 真假条件模板对（索引 [0,2]、[1,3]）
    const pairs = [
      [0, 2],
      [1, 3],
    ];
    for (const [ti, fi] of pairs) {
      if (!templates[ti] || !templates[fi]) continue;
      const trueFilled = fillPayload(templates[ti], { orig });
      const falseFilled = fillPayload(templates[fi], { orig });
      const truePayload = this.obfuscateValue(ctx, trueFilled);
      const falsePayload = this.obfuscateValue(ctx, falseFilled);

      const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
      const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
      const tBody = String(rTrue?.data ?? '');
      const fBody = String(rFalse?.data ?? '');

      // 真条件应≈原始页面（AND 1=1 等价正常业务）、假条件应偏离；
      // 三者同时满足才判定，避免随机动态内容（时间戳/anti-CSRF token）造成误报。
      if (
        this._isMeaningfulDiff(tBody, fBody) &&
        this._similarToBaseline(tBody, baselines) &&
        !this._similarToBaseline(fBody, baselines)
      ) {
        result.vulnerable = true;
        result.dbms = dbms;
        result.evidence = `布尔注入确认：真条件≈原始响应(${tBody.length}B)、假条件偏离(${fBody.length}B)`;
        result.payloads = [truePayload, falsePayload];
        point.confirmed = true;
        point.technique = 'boolean';
        point.dbms = dbms;
        break;
      }
    }
    return result;
  }

  // —— 鲁棒分支：基线指纹集 + 真假对重复采样一致率 + 统计显著性判定（抗抖动/动态内容误报）——
  // 基线 + 每对真假采样均改为限并发（sendConcurrent），抵消 v2 串行 await 的 ~2.8× 开销；
  // trace 每个样本存 excerpt 片段，每对存逐采样真假差异（lenDelta/firstDiffOffset/changedSnippet），供前端展开审计。
  async _robustDetect(ctx, result, templates, rb) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    const sigZ = rb.booleanSignificanceZ ?? 1.645;
    const concurrency = rb.concurrency || 4;

    // 1) 基线指纹集（并发采样，比 legacy 串行更稳更快）
    const baselineReqs = [];
    for (let i = 0; i < rb.baselineSamples; i++) {
      baselineReqs.push(this.buildRequest(target, point, orig));
    }
    const baselineResps = await this.sendConcurrent(httpClient, ctx, baselineReqs, {}, concurrency);
    const baselines = baselineResps.map((r) => this._bodyOf(r));
    const similarToBaseline = (body) => this._similarToBaseline(body, baselines);

    // 1.1) 基线自然抖动率（"噪声地板"）
    const baselineNoiseRateVal = baselineNoiseRate(baselines, (a, b) => this._similar(a, b));

    // 1.2) 自适应一致率门槛：稳定目标落回下限(严格控误报)，抖动目标抬高门槛(要求更清晰信号)
    const minRatio = rb.adaptive
      ? adaptiveMinStable(baselineNoiseRateVal, rb.adaptiveHeadroom, rb.minStableRatioFloor, rb.minStableRatioCap)
      : rb.minStableRatio;

    // 2) 遍历真假对，首个稳定对即 break（保留短路语义）
    // 自适应采样：基线噪声高时多采 1 次，提升抖动目标上的估计可靠性（有上限，控性能）
    const effSamples = rb.adaptive && baselineNoiseRateVal > 0.3
      ? Math.min(rb.booleanSamples + 1, 6)
      : rb.booleanSamples;
    const pairs = [[0, 2], [1, 3]];
    const tracePairs = [];
    for (const [ti, fi] of pairs) {
      if (!templates[ti] || !templates[fi]) continue;
      const truePayload = this.obfuscateValue(ctx, fillPayload(templates[ti], { orig }));
      const falsePayload = this.obfuscateValue(ctx, fillPayload(templates[fi], { orig }));

      // 真/假各 effSamples 次，合并并发发送（限制并发度，避免打爆目标/触发 WAF）
      const reqs = [];
      for (let s = 0; s < effSamples; s++) reqs.push(this.buildRequest(target, point, truePayload));
      for (let s = 0; s < effSamples; s++) reqs.push(this.buildRequest(target, point, falsePayload));
      const resps = await this.sendConcurrent(httpClient, ctx, reqs, {}, concurrency);
      const tBodies = resps.slice(0, effSamples).map((r) => this._bodyOf(r));
      const fBodies = resps.slice(effSamples).map((r) => this._bodyOf(r));

      // 三一致率：真≈基线 / 假≠基线 / tBody 与 fBody 有意义差异
      const trueRatio = similarityRate(tBodies, similarToBaseline, true);
      const falseRatio = similarityRate(fBodies, similarToBaseline, false);
      let meaningfulHits = 0;
      for (let s = 0; s < effSamples; s++) {
        if (this._isMeaningfulDiff(tBodies[s], fBodies[s])) meaningfulHits++;
      }
      const meaningfulRatio = meaningfulHits / effSamples;

      // 统计显著性：false 条件偏离基线的比例，是否显著高于基线自身的自然抖动率。
      const z = twoProportionZ(falseRatio, effSamples, baselineNoiseRateVal, baselines.length);
      const significant = isSignificant(falseRatio, effSamples, baselineNoiseRateVal, baselines.length, sigZ);

      // 逐采样真假差异摘要（前端时间线展开看"到底差在哪"）
      const diffs = [];
      for (let s = 0; s < effSamples; s++) {
        const off = this._firstDiffOffset(tBodies[s], fBodies[s]);
        diffs.push({
          idx: s,
          lenDelta: fBodies[s].length - tBodies[s].length,
          firstDiffOffset: off,
          changedSnippet: off < 0 ? '' : fBodies[s].slice(Math.max(0, off - 20), off + 100),
        });
      }

      tracePairs.push({
        ti,
        fi,
        trueSamples: tBodies.map((b, i) => ({ idx: i, len: b.length, likeBaseline: similarToBaseline(b), excerpt: this._excerpt(b) })),
        falseSamples: fBodies.map((b, i) => ({ idx: i, len: b.length, likeBaseline: similarToBaseline(b), excerpt: this._excerpt(b) })),
        trueRatio,
        falseRatio,
        meaningfulRatio,
        z,
        significant,
        diffs,
      });

      if (
        trueRatio >= minRatio &&
        falseRatio >= minRatio &&
        meaningfulRatio >= minRatio &&
        significant
      ) {
        result.vulnerable = true;
        result.dbms = dbms;
        result.evidence = `布尔注入确认(统计${rb.adaptive ? '·自适应' : ''}): 真≈基线${trueRatio.toFixed(2)}、假≠基线${falseRatio.toFixed(2)}、差异${meaningfulRatio.toFixed(2)}、基线噪声${baselineNoiseRateVal.toFixed(2)}、门槛${minRatio.toFixed(2)}、z=${z === null ? 'NA' : z.toFixed(2)}(显著)`;
        result.payloads = [truePayload, falsePayload];
        point.confirmed = true;
        point.technique = 'boolean';
        point.dbms = dbms;
        result.trace = {
          technique: 'boolean',
          adaptive: !!rb.adaptive,
          baselineNoiseRate: baselineNoiseRateVal,
          minStable: minRatio,
          baselineSamples: baselines.map((b, i) => ({ idx: i, len: b.length, likeBaseline: true, excerpt: this._excerpt(b) })),
          pairs: tracePairs,
          decision: 'vulnerable',
        };
        break;
      }
    }
    // 未命中也透传轨迹（说明"为何判干净"），便于前端展示证据链
    if (!result.trace) {
      result.trace = {
        technique: 'boolean',
        adaptive: !!rb.adaptive,
        baselineNoiseRate: baselineNoiseRateVal,
        minStable: minRatio,
        baselineSamples: baselines.map((b, i) => ({ idx: i, len: b.length, likeBaseline: true, excerpt: this._excerpt(b) })),
        pairs: tracePairs,
        decision: 'clean',
      };
    }
    return result;
  }

  // 从 sendConcurrent 的返回元素安全取响应体（并发失败降级空串，不影响一致率计算）
  _bodyOf(r) {
    if (!r || r.__error || !r.resp) return '';
    return String(r.resp?.data ?? '');
  }

  // 响应片段（截断控制 trace 体积，便于人工审计"页面主体变化"）
  _excerpt(s, max = 160) {
    return String(s == null ? '' : s).slice(0, max);
  }

  // 首个不同字符下标（-1 表示完全相同）
  _firstDiffOffset(a, b) {
    const m = Math.min(a.length, b.length);
    for (let i = 0; i < m; i++) if (a[i] !== b[i]) return i;
    if (a.length !== b.length) return m;
    return -1;
  }

  // 排除纯空白差异，要求有实质不同
  _isMeaningfulDiff(a, b) {
    return (
      Math.abs(a.length - b.length) > 1 ||
      a.replace(/\s+/g, '') !== b.replace(/\s+/g, '')
    );
  }

  // 与任一基线样本相似（容忍动态内容的轻微抖动）
  _similarToBaseline(body, baselines) {
    return baselines.some((b) => this._similar(body, b));
  }

  // 相似判定：长度差在容差内，且最长公共前缀覆盖较短者 85% 以上
  _similar(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > Math.max(24, lb * 0.12)) return false;
    const m = Math.min(la, lb);
    let common = 0;
    while (common < m && a[common] === b[common]) common++;
    return common >= m * 0.85;
  }
}

export default BooleanBlindDetector;

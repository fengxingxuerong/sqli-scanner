import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload, buildClausePairs } from '../payloads.js';
import { selectPayloads } from '../payloadRegistry.js';
import { similarityRate, twoProportionZ, isSignificant, baselineNoiseRate, adaptiveMinStable, chunkSimilarity } from '../../core/statsHelper.js';

// 空白字符判定（对齐 JS /\s/ 语义，避免每次 new RegExp）：
// 热路径 _isMeaningfulDiff 逐字符调用本判定，旧实现 `/\s/.test(ch)` 每次调用都走正则引擎
// （大 body 全等时逐字符扫全串，100KB 级 = 10 万次正则 test ≈ 数 ms）。
// 改为 charCode 快速判定：ASCII 空白直判；罕见 Unicode 空白走 Set（与 /\s/ 完全一致）。
const WS_RARE = new Set([0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);
function isWsChar(ch) {
  const c = ch.charCodeAt(0);
  if (c < 0x80) return c === 0x20 || (c >= 0x09 && c <= 0x0d);
  if (c >= 0x2000 && c <= 0x200a) return true; // en quad..hair space（\s 含 2000-200a）
  return WS_RARE.has(c);
}

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
    const { point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'boolean');
    const templates = (PAYLOADS[dbms] && PAYLOADS[dbms].boolean) || PAYLOADS.MySQL.boolean;

    let primary;
    // T1 响应匹配多指标（--string/--not-string/--text-only/--code/--regexp/--titles）：
    // 用户显式配置时优先用其判定真/假；未配置回退 blindRobust 统计 + 分块比对（默认路径不变）。
    if (this.hasExplicitMatch(ctx.config)) {
      primary = await this._matchMetricsDetect(ctx, result, templates);
    } else {
      // 双路径：blindRobust 未启用（或未配置）时走现状 legacy 逻辑，确保零回归
      const rb = ctx.config?.blindRobust;
      if (!rb || rb.enabled === false) {
        primary = await this._legacyDetect(ctx, result, templates);
      } else {
        primary = await this._robustDetect(ctx, result, templates, rb);
      }
    }
    // 子句位置变体轮（对标 sqlmap clause 属性体系）：主模板未命中且 level>=2 时追加，
    // 覆盖 ORDER BY / GROUP BY / HAVING / LIMIT 位置注入点（有界，level=1 完全不投放）。
    if (!primary.vulnerable && this._clauseRoundEnabled(ctx)) {
      return this._clauseRound(ctx, primary);
    }
    return primary;
  }

  // level>=2 才消费子句位置变体（对标 sqlmap --level；level=1/undefined 请求数与行为零变化）。
  // [G3-FIX] 原实现在 useRegistry=true 时整体跳过子句轮→位置探测缺失；现主轮收敛为 where 条目，
  // 子句轮独立承担 ORDER BY/GROUP BY/HAVING/LIMIT 位置探测（两条路径统一，useRegistry 无差异）
  _clauseRoundEnabled(ctx) {
    // !(level >= 2) 正确处理 NaN（undefined → NaN → false → !false → true → skip）
    if (!(Number(ctx.config && ctx.config.level) >= 2)) return false;
    // [回归修复 2026-09-06] --test-filter/--test-skip 是全局约束（sqlmap 语义：被过滤的
    // <test> 不该投放）。G3-FIX 让子句轮独立于注册表运行后，过滤不再约束子句变体 →
    // 用户指定"只跑 X / 跳过 Y"时仍会投放被排除的 payload（boolRegistry 两个用例回归）。
    // 判定：按同样过滤条件筛选子句类条目，无剩余则禁用子句轮。
    const cfg = ctx.config || {};
    if (cfg.testFilter || cfg.testSkip) {
      try {
        const clauseEntries = selectPayloads({
          dbms: ctx.dbms,
          technique: 'boolean',
          clause: ['orderby', 'groupby', 'having', 'limit'],
          testFilter: cfg.testFilter,
          testSkip: cfg.testSkip,
        });
        if (clauseEntries.length === 0) return false;
      } catch {
        return false; // 解析异常 → 保守禁用子句轮（不改变主轮语义）
      }
    }
    return true;
  }

  /**
   * 获取布尔真假条件对（统一入口，支持注册表路径与索引回退路径）。
   *
   * config.useRegistry === true 时从 selectPayloads() 按 level/risk/testFilter/testSkip
   * 筛选声明式注册表条目（对标 sqlmap <test> 的 level/risk/dbms 过滤语义），
   * 每条 entry 的 template + falseTemplate 构成一对；
   * 否则回退到固定索引对 [0,2]/[1,3]/[4,5]/[6,7]（与历史行为完全一致，零回归）。
   *
   * boundary 感知对在两条路径中均作为首对优先尝试（探测到闭合前缀时用
   * 「闭合前缀 + AND 1=1/1=2 + 注释」构造，对标 sqlmap boundary 属性）。
   *
   * @param {object} ctx 检测上下文 { point, config, dbms }
   * @param {string[]} templates 扁平 payload 模板数组（PAYLOADS[dbms].boolean），仅回退路径使用
   * @returns {Array<{ti:number, fi:number, truePayload?:string, falsePayload?:string, id?:string, isBoundary?:boolean}>}
   */
  _getBooleanPairs(ctx, templates) {
    const { point, config } = ctx;
    const orig = point.originalValue || '1';
    const risk = Number(config && config.risk) || 1;
    const pairs = [];

    // boundary 感知对（两条路径共用）：探测到闭合前缀时优先尝试
    if (point.boundary) {
      pairs.push({
        ti: -1,
        fi: -2,
        truePayload: this.obfuscateValue(ctx, `${orig}${point.boundary} AND 1=1-- -`),
        falsePayload: this.obfuscateValue(ctx, `${orig}${point.boundary} AND 1=2-- -`),
        isBoundary: true,
      });
    }

    if (config && config.useRegistry === true) {
      // 注册表路径：按 level/risk/testFilter/testSkip 筛选声明式条目
      const level = Number(config.level) > 0 ? Number(config.level) : undefined;
      const entries = selectPayloads({
        dbms: ctx.dbms,
        technique: 'boolean',
        level,
        risk,
        clause: ['where'], // [G3-FIX] 主轮 only where（位置变体由子句轮承担）
        testFilter: config.testFilter,
        testSkip: config.testSkip,
      });
      for (const e of entries) {
        if (!e.falseTemplate) continue;
        pairs.push({
          ti: -1,
          fi: -1,
          truePayload: this.obfuscateValue(ctx, fillPayload(e.template, { orig })),
          falsePayload: this.obfuscateValue(ctx, fillPayload(e.falseTemplate, { orig })),
          id: e.id,
        });
      }
    } else {
      // 回退路径：固定索引对（与历史行为一致，零回归）
      // 真假条件模板对（索引 [0,2] 单引号、[1,3] 双引号、[4,5] 数字型无引号）
      const idxPairs = [
        { ti: 0, fi: 2 },
        { ti: 1, fi: 3 },
        { ti: 4, fi: 5 },
      ];
      // risk>=2 时额外尝试 OR-based 布尔对（[6,7]，对标 sqlmap --risk 语义）
      if (risk >= 2 && templates[6] && templates[7]) idxPairs.push({ ti: 6, fi: 7 });
      for (const p of idxPairs) {
        if (!templates[p.ti] || !templates[p.fi]) continue;
        pairs.push({ ti: p.ti, fi: p.fi });
      }
    }
    return pairs;
  }

  // 构造注入确认的证据描述（统一 boundary/index/registry 三种来源的证据格式）
  _boolEvidence(ctx, p, tLen, fLen) {
    const tag = p.isBoundary
      ? `(boundary=${ctx.point.boundary})`
      : p.id
        ? `(test=${p.id})`
        : '';
    return `布尔注入确认${tag}：真条件≈原始响应(${tLen}B)、假条件偏离(${fLen}B)`;
  }

  // —— 子句位置布尔轮：真假对覆盖 ORDER BY（逗号拼接）/ GROUP BY（HAVING 追加）/ HAVING / LIMIT（表达式）——
  // 判定与 legacy 一致：真≈基线 且 假≠基线 且 真假有意义差异（显式匹配指标配置时改用 matchMetrics）。
  async _clauseRound(ctx, result) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    const pairs = buildClausePairs(dbms && PAYLOADS[dbms] ? dbms : 'MySQL', { orig }, { maxTotal: 6 });
    if (!pairs.length) return result;
    // 基线 2 次（与 legacy 同参），供「真≈基线 / 假≠基线」判定
    const baselines = [];
    for (let i = 0; i < 2; i++) {
      const r = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
      baselines.push(String(r?.data ?? ''));
    }
    const explicit = this.hasExplicitMatch(ctx.config);
    for (const pair of pairs) {
      const truePayload = this.obfuscateValue(ctx, pair.truePayload);
      const falsePayload = this.obfuscateValue(ctx, pair.falsePayload);
      const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
      const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
      if (explicit) {
        if (this.matchMetrics(rTrue, rFalse, ctx.config) === true) {
          this._markClauseHit(result, point, dbms, pair, truePayload, falsePayload, `响应匹配多指标（${this._metricLabels(ctx.config)}）`);
          break;
        }
        continue;
      }
      const tBody = String(rTrue?.data ?? '');
      const fBody = String(rFalse?.data ?? '');
      // 状态码/content-length 粗筛（P2-P8 同构扩展）：命中即跳过 body 精细比对
      const quickDiff = this._statusDiffer(rTrue, rFalse) || this._lengthDiffer(rTrue, rFalse);
      if (
        (quickDiff || this._isMeaningfulDiff(tBody, fBody)) &&
        this._similarToBaseline(tBody, baselines) &&
        !this._similarToBaseline(fBody, baselines)
      ) {
        this._markClauseHit(
          result,
          point,
          dbms,
          pair,
          truePayload,
          falsePayload,
          `真条件≈原始响应(${tBody.length}B)、假条件偏离(${fBody.length}B)`
        );
        break;
      }
    }
    return result;
  }

  // 子句轮命中：统一回填结果（evidence 标注 clause 位置，便于前端审计）
  _markClauseHit(result, point, dbms, pair, truePayload, falsePayload, detail) {
    result.vulnerable = true;
    result.dbms = dbms;
    result.evidence = `布尔注入确认(子句位置 clause=${pair.clause}): ${detail}`;
    result.payloads = [truePayload, falsePayload];
    point.confirmed = true;
    point.technique = 'boolean';
    point.dbms = dbms;
  }

  // —— 响应匹配多指标判定路径：逐真假对采样 1 次，用 matchMetrics（显式指标）判定真≠假 ——
  async _matchMetricsDetect(ctx, result, templates) {
    const { httpClient, target, point, dbms } = ctx;
    const orig = point.originalValue || '1';
    const pairs = this._getBooleanPairs(ctx, templates);
    for (const p of pairs) {
      if (p.ti >= 0 && (!templates[p.ti] || !templates[p.fi])) continue;
      const truePayload = p.truePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.ti], { orig }));
      const falsePayload = p.falsePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.fi], { orig }));
      const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
      const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
      const signal = this.matchMetrics(rTrue, rFalse, ctx.config);
      if (signal === true) {
        result.vulnerable = true;
        result.dbms = dbms;
        result.evidence = `布尔注入确认(响应匹配多指标): 真/假响应命中显式匹配指标（${this._metricLabels(ctx.config)}）`;
        result.payloads = [truePayload, falsePayload];
        point.confirmed = true;
        point.technique = 'boolean';
        point.dbms = dbms;
        break;
      }
    }
    return result;
  }

  // —— 现状逻辑（useRegistry=false 时行为不变；true 时从注册表选取真假对）——
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

    // 自动动态块识别（T2）：开启时排除基线中的动态块再做相似度比对（默认关闭，路径不变）
    const dynSimilar = this.buildDynamicSimilar(baselines, ctx.config);
    const similarToBaseline = dynSimilar
      ? (body) => baselines.some((b) => dynSimilar(body, b))
      : (body) => this._similarToBaseline(body, baselines);
    const meaningfulDiff = dynSimilar
      ? (a, b) => !dynSimilar(a, b)
      : (a, b) => this._isMeaningfulDiff(a, b);

    // 统一真假对获取（boundary 感知对优先 + 注册表/索引对）
    const pairs = this._getBooleanPairs(ctx, templates);
    for (const p of pairs) {
      if (p.ti >= 0 && (!templates[p.ti] || !templates[p.fi])) continue;
      const truePayload = p.truePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.ti], { orig }));
      const falsePayload = p.falsePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.fi], { orig }));

      const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
      const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
      const tBody = String(rTrue?.data ?? '');
      const fBody = String(rFalse?.data ?? '');

      // P2-P8 CPU 比对下沉：状态码粗筛——真/假状态不同即视为有意义差异，跳过 body 精细比对
      // content-length 短路（T3）：头长度差异超容差同样跳过 body 全文 LCP/分块比对
      const quickDiff =
        this._statusDiffer(rTrue, rFalse) || this._lengthDiffer(rTrue, rFalse);
      // 真条件应≈原始页面（AND 1=1 等价正常业务）、假条件应偏离；
      // 三者同时满足才判定，避免随机动态内容（时间戳/anti-CSRF token）造成误报。
      if (
        (quickDiff || meaningfulDiff(tBody, fBody)) &&
        similarToBaseline(tBody) &&
        !similarToBaseline(fBody)
      ) {
        result.vulnerable = true;
        result.dbms = dbms;
        result.evidence = this._boolEvidence(ctx, p, tBody.length, fBody.length);
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
    // 自动动态块识别（T2）：开启时排除基线动态块，相似度/噪声率/真假差异均按动态块过滤
    const dynSimilar = this.buildDynamicSimilar(baselines, ctx.config);
    const similarToBaseline = dynSimilar
      ? (body) => baselines.some((b) => dynSimilar(body, b))
      : (body) => this._similarToBaseline(body, baselines);
    const meaningfulDiff = dynSimilar
      ? (a, b) => !dynSimilar(a, b)
      : (a, b) => this._isMeaningfulDiff(a, b);

    // 1.1) 基线自然抖动率（"噪声地板"）
    const baselineNoiseRateVal = dynSimilar
      ? baselineNoiseRate(baselines, (a, b) => dynSimilar(a, b))
      : baselineNoiseRate(baselines, (a, b) => this._similar(a, b));

    // 1.2) 自适应一致率门槛：稳定目标落回下限(严格控误报)，抖动目标抬高门槛(要求更清晰信号)
    const minRatio = rb.adaptive
      ? adaptiveMinStable(baselineNoiseRateVal, rb.adaptiveHeadroom, rb.minStableRatioFloor, rb.minStableRatioCap)
      : rb.minStableRatio;

    // 2) 遍历真假对，首个稳定对即 break（保留短路语义）
    // 自适应采样：基线噪声高时多采 1 次，提升抖动目标上的估计可靠性（有上限，控性能）
    const effSamples = rb.adaptive && baselineNoiseRateVal > 0.3
      ? Math.min(rb.booleanSamples + 1, 6)
      : rb.booleanSamples;
    // 统一真假对获取（boundary 感知对优先 + 注册表/索引对）
    const pairs = this._getBooleanPairs(ctx, templates);
    const tracePairs = [];
    for (const p of pairs) {
      const { ti, fi } = p;
      if (ti >= 0 && (!templates[ti] || !templates[fi])) continue;
      const truePayload = p.truePayload ?? this.obfuscateValue(ctx, fillPayload(templates[ti], { orig }));
      const falsePayload = p.falsePayload ?? this.obfuscateValue(ctx, fillPayload(templates[fi], { orig }));

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
        // P2-P8 CPU 比对下沉：状态码粗筛——真/假状态不同即视为有意义差异，跳过 body 精细比对
        // content-length 短路（T3）：头长度差异超容差同样跳过 body 全文 LCP/分块比对
        const tRes = resps[s];
        const fRes = resps[effSamples + s];
        if (
          this._statusDiffer(tRes?.resp, fRes?.resp) ||
          this._lengthDiffer(tRes?.resp, fRes?.resp) ||
          meaningfulDiff(tBodies[s], fBodies[s])
        ) meaningfulHits++;
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

  // 状态码粗筛（P2-P8 CPU 比对下沉）：两者状态码均可知且不同 → 响应明显不同，
  // 调用方可跳过 body 精细比对（大 body 省 LCP/分块 hash）。
  _statusDiffer(a, b) {
    return a?.status != null && b?.status != null && a.status !== b.status;
  }

  // 响应头数值化 content-length（无头/非数值返回 null；axios 头可能是数组，取首值）
  _contentLengthOf(res) {
    const h = res?.headers;
    if (!h) return null;
    const raw = h['content-length'] ?? h['Content-Length'];
    if (raw == null) return null;
    const n = Number(Array.isArray(raw) ? raw[0] : raw);
    return Number.isFinite(n) && n >= 0 ? n : null;
  }

  // content-length 短路（T3，P2-P8 状态码粗筛的同构扩展）：两响应均带数值 content-length
  // 且差异超出容差（与 _similar 长度容差同参：max(24, 较小者 12%)）→ 直接判「不同」，
  // 调用方跳过 body 全文 LCP/分块比对，省大 body CPU 全扫。
  // 头缺失/不可解析时返回 false（回落 body 比对，mock/老网关行为不变）。
  _lengthDiffer(a, b) {
    const la = this._contentLengthOf(a);
    const lb = this._contentLengthOf(b);
    if (la == null || lb == null) return false;
    return Math.abs(la - lb) > Math.max(24, Math.min(la, lb) * 0.12);
  }

  // 排除纯空白差异，要求有实质不同。
  // P2-P8 零分配流式比对：语义等价 a.replace(/\s+/g,'') !== b.replace(/\s+/g,'')，
  // 但不对大 body 产生两份整串拷贝（省 CPU 与 GC 压力）。
  _isMeaningfulDiff(a, b) {
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > 1) return true;
    let i = 0;
    let j = 0;
    while (i < la || j < lb) {
      while (i < la && this._isWs(a[i])) i++;
      while (j < lb && this._isWs(b[j])) j++;
      if ((i < la ? a[i] : null) !== (j < lb ? b[j] : null)) return true;
      i++;
      j++;
    }
    return false;
  }

  // 空白字符判定（charCode 快速路径，语义与 /\s/ 一致，见文件顶部 isWsChar）
  _isWs(ch) {
    return isWsChar(ch);
  }

  // 与任一基线样本相似（容忍动态内容的轻微抖动）
  _similarToBaseline(body, baselines) {
    return baselines.some((b) => this._similar(body, b));
  }

  // 相似判定：长度差在容差内，且最长公共前缀覆盖较短者 85% 以上。
  // P1-P1 轻量布尔指标：大 body（> 64KB）时以「长度差」为主判定（长度差超容差即不相似，直接返回），
  // 避免对超大响应体做逐字符 LCP 扫描，省 CPU；小 body 才做精确 LCP（行为不变，零回归）。
  // P1-D4 响应相似度升级：LCP 未达标但「分块相似率 ≥ 0.85」时兜底判相似——
  // 首部动态内容（时间戳/anti-CSRF token）会让 LCP 崩塌，分块比对不受首块差异影响，提升召回。
  _similar(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    const lenDelta = Math.abs(la - lb);
    // 大 body 快速路径：长度差超出容差 → 直接判定不相似，跳过 LCP
    if (lenDelta > Math.max(24, lb * 0.12)) return false;
    // 大 body 且长度差在容差内 → 用「首尾+中间采样」近似判定（省逐字符扫描）
    if (la > 65536 || lb > 65536) {
      const head = 256;
      const tail = 256;
      if (a.slice(0, head) !== b.slice(0, head)) return false;
      // ★FIX [P0]：尾部比较不限于 la===lb，各自取末尾 256 字符；
      // 增加中间采样点（50% 处取 256 字符），覆盖差异在 body 中间的情况。
      // 旧实现仅 la===lb 时才比尾部、且只比头尾 → 大 body 中间差异漏报。
      if (a.slice(-tail) !== b.slice(-tail)) return false;
      const midA = a.slice(Math.floor(la / 2), Math.floor(la / 2) + head);
      const midB = b.slice(Math.floor(lb / 2), Math.floor(lb / 2) + head);
      if (midA !== midB) return false;
      return true;
    }
    const m = Math.min(la, lb);
    let common = 0;
    while (common < m && a[common] === b[common]) common++;
    if (common >= m * 0.85) return true;
    // P1-D4：LCP 不达标时用分块相似率兜底（首部动态内容场景）
    return chunkSimilarity(a, b) >= 0.85;
  }
}

export default BooleanBlindDetector;

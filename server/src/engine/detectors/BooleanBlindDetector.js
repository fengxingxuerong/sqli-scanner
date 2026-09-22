import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload, buildClausePairs } from '../payloads.js';
import { selectPayloads, orderEntriesByBoundary } from '../payloadRegistry.js';
import { similarityRate, twoProportionZ, isSignificant, baselineNoiseRate, adaptiveMinStable, chunkSimilarity } from '../../core/statsHelper.js';

// 空白字符判定（对齐 JS /\s/ 语义，避免每次 new RegExp）：
// 热路径 _isMeaningfulDiff 逐字符调用本判定，旧实现 `/\s/.test(ch)` 每次调用都走正则引擎
// （大 body 全等时逐字符扫全串，100KB 级 = 10 万次正则 test ≈ 数 ms）。
// 改为 charCode 快速判定：ASCII 空白直判；罕见 Unicode 空白走 Set（与 /\s/ 完全一致）。
const WS_RARE = new Set([0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);

// —— 动态数值归一化（[P1-FIX 2026-09-08] 安全点误报根治）——
// 场景：页面含秒级时间戳/计数器（如 `<!-- generated at 1788758518 -->`）。基线 5 次采样
// 通常落在同一秒内 → 动态块识别学到「无动态块」→ 回落默认比对；后续真/假采样跨秒时，
// 时间戳数字变化让 LCP 在首部崩塌、分块相似率也被稀释 → 真/假被判「偏离基线」→ 安全点误报。
// 判据（保守，仅兜底）：两串长度相同，且把每段「≥8 位连续数字」替换成同一占位符后文本
// 完全一致 → 差异仅来自动态数值，判相似。零额外请求。
// 阈值取 8 位的理由：Unix 秒级时间戳 10 位 / 毫秒 13 位被归一化；而列表编号、行号、ID 等
// 短数字（1-5 位）保留语义——它们常是真假条件的真实差异（如 user_1 / user_2），一概归一化
// 会把真注入信号吞掉（blindRobust 高抖动用例即此形态）。
const LONG_NUM_RUN_RE = /\d{8,}/g;
function numericNormalized(s) {
  return s.replace(LONG_NUM_RUN_RE, '\u0000');
}
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
      const entries = orderEntriesByBoundary(
        selectPayloads({
          dbms: ctx.dbms,
          technique: 'boolean',
          level,
          risk,
          clause: ['where'], // [G3-FIX] 主轮 only where（位置变体由子句轮承担）
          testFilter: config.testFilter,
          testSkip: config.testSkip,
        }),
        ctx.point?.boundary
      ); // [G1] 按探测闭合族排序：兼容变体优先（主轮 break 早退更早兑现，省请求）
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
      // risk>=2 时额外尝试 OR-based 布尔对（对标 sqlmap --risk 语义）
      // [6] `OR '1'='1'` 作真条件、[7] `OR '1'='2'` 作假条件：适用于「基线已有数据、
      // OR 恒真不改变结果集」的目标（sqlmap OR 注入语义，risk>=2 历史行为，保持不变）。
      if (risk >= 2 && templates[6] && templates[7]) idxPairs.push({ ti: 6, fi: 7 });
      // [P1-FIX 2026-09-10 实战实测] 空基线兜底对（顺序与上面相反）：
      // 参数原值查不到任何行（失效 id / 已删除用户 / 需鉴权不可见）时，AND 真/假双双落在
      // 同一个空结果集 → 真≈基线 且 假≈基线 → 布尔通道静默失效（实测：真 MySQL
      // `username='ghost'` 只剩 error；插回该用户立刻 union+error+boolean 全通）。
      // 此场景下「真条件」是 `OR '1'='2'`（仍为空、≈基线）、「假条件」是 `OR '1'='1'`（命中全表）。
      // 两种 OR 顺序覆盖两种基线形态，故各留一对；本对排最后，仅当前面对全部失败才轮到。
      // 代价：主轮未命中的点 +2 请求。关闭：config.booleanOrFallback = false。
      if (config?.booleanOrFallback !== false && templates[6] && templates[7]) {
        idxPairs.push({ ti: 7, fi: 6 });
      }
      for (const p of idxPairs) {
        if (!templates[p.ti] || !templates[p.fi]) continue;
        pairs.push({ ti: p.ti, fi: p.fi });
      }
    }
    // [P1-FIX 2026-09-10 实战实测] 空基线降级对（OR 型，仅 AND 型全部失败后才轮到）
    // 场景：参数原值查不到任何行（失效 id / 已删除用户 / 需鉴权不可见）时，
    //   `AND 1=1` 与 `AND 1=2` 双双落在同一个空结果集 → 真/假响应完全一致 → 布尔通道静默失效。
    // 实测（真 MySQL）：`WHERE username='ghost'`（库内无此行）只剩 error 命中；把该用户插回后
    //   立刻 union+error+boolean 全通——差别只在「原值查不查得到数据」。
    // 判据（对齐 legacy 语义：真≈基线、假≠基线）：
    //   真条件取 `OR 1=2`（等价于原查询 → 仍≈基线），假条件取 `OR 1=1`（命中全表 → 偏离基线）。
    //   非空基线场景同样成立（OR 1=2=原结果，OR 1=1=全表），故作为通用兜底对放在最后。
    // 仅在已探测到闭合前缀（boundary）时投放，避免无闭合字符串产生语法错误噪声。
    // 关闭：config.booleanOrFallback = false。
    if (point.boundary && config?.booleanOrFallback !== false) {
      pairs.push({
        ti: -1,
        fi: -1,
        truePayload: this.obfuscateValue(ctx, `${orig}${point.boundary} OR 1=2-- -`),
        falsePayload: this.obfuscateValue(ctx, `${orig}${point.boundary} OR 1=1-- -`),
        id: 'or_fallback',
      });
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
      // [FIX 2026-09-21] 空/失败的 body 不得进动态块学习（详见 _robustDetect 里的同名注释）：
      // 本分支只采样 2 次，混入 1 个空串时 pairs=1、diffCount=1 → 1/1 > 0.5 →
      // 全部块判成动态块 → 判定恒"相似" → boolean 漏报。比 5 次采样的分支更脆。
      const body = String(r?.data ?? '');
      if (body) baselines.push(body);
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
      const tBody = this._stripReflected(String(rTrue?.data ?? ''), truePayload, orig);
      const fBody = this._stripReflected(String(rFalse?.data ?? ''), falsePayload, orig);
      // [P0-FIX 2026-09-11] WAF 拦截页防线：真/假任一侧被 WAF 拦成拦截页时，差异来自
      // WAF 拦截而非 SQL 执行（waf-real echo 安全对照误报根因，2/2 复现）——本对不算命中。
      if (this._pairPollutedByWafBlock(rTrue, rFalse)) continue;
      // 状态码/content-length 粗筛（P2-P8 同构扩展）：命中即跳过 body 精细比对
      const quickDiff = this._statusDiffer(rTrue, rFalse) || this._lengthDiffer(rTrue, rFalse);
      if (
        (quickDiff || this._isMeaningfulDiff(tBody, fBody)) &&
        this._similarToBaseline(tBody, baselines) &&
        !this._similarToBaseline(fBody, baselines)
      ) {
        // [P0-FIX 2026-09-10 实战评测] 子句轮单次比较在「动态内容页面」上会偶发误报：
        // 随机 nonce/时间戳让假条件响应长度偶然偏离基线（实测 /safe/rand 4 次误报 1 次），
        // 单次采样无法区分「注入导致的差异」与「页面自身抖动」。
        // 与 legacy 主轮一致的处置：命中前先过「组间稳定差异」复核（真/假各补采样本，
        // 要求组内自相似 + 差异可复现 + 非数值/随机噪声）。开关 boolStableDiff 默认开启。
        if (ctx.config?.boolStableDiff !== false) {
          const n = Math.min(3, Math.max(2, Number(ctx.config?.boolStableDiffSamples) || 3));
          const tBodies = [tBody];
          const fBodies = [fBody];
          let usable = !(this.unusableOf(rTrue) || this.unusableOf(rFalse));
          for (let s = 1; s < n && usable; s++) {
            const rrT = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
            const rrF = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
            if (this.unusableOf(rrT) || this.unusableOf(rrF)) { usable = false; break; }
            tBodies.push(String(rrT?.data ?? ''));
            fBodies.push(String(rrF?.data ?? ''));
          }
          if (!usable) continue;
          const sd = this._stableDiffJudge(tBodies, fBodies);
          if (!sd) continue; // 差异不可复现（动态噪声）→ 本对不算命中，继续下一对
          // [P0-FIX 2026-09-11] 反射回显甄别：差异片段=payload 自身被页面回显 → 非注入信号
          if (this._isReflectedDiff(sd.tSpan, sd.fSpan, truePayload, falsePayload)) continue;
          this._markClauseHit(
            result,
            point,
            dbms,
            pair,
            truePayload,
            falsePayload,
            `真条件≈原始响应(${tBody.length}B)、假条件偏离(${fBody.length}B)；组间稳定差异复核通过（${n} 样本一致）`
          );
          break;
        }
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
    // [P0-FIX 2026-09-09] 区别「测过、无差异」与「没法测」：不可用的对照对不记为阴性；
    // 全部对照都不可用时把本点标成未决（报告 reliable=false），而不是留个「未检出」。
    let attempted = 0;
    let undetermined = 0;
    let lastReason = '';
    for (const p of pairs) {
      if (p.ti >= 0 && (!templates[p.ti] || !templates[p.fi])) continue;
      const truePayload = p.truePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.ti], { orig }));
      const falsePayload = p.falsePayload ?? this.obfuscateValue(ctx, fillPayload(templates[p.fi], { orig }));
      const rTrue = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
      const rFalse = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
      attempted++;
      const why = this.unusableOf(rTrue) || this.unusableOf(rFalse);
      if (why) {
        undetermined++;
        lastReason = why;
        continue;
      }
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
    if (!result.vulnerable && attempted > 0 && undetermined === attempted) {
      result.inconclusive = true;
      result.inconclusiveReason = `${undetermined}/${attempted} 组布尔对照因「${lastReason || '响应不可用'}」未得出有效结论`;
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
      // [FIX 2026-09-21] 同 _robustDetect / _clauseRound：空/失败的 body 不进动态块学习
      const body = String(r?.data ?? '');
      if (body) baselines.push(body);
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
      // [P0-FIX 2026-09-11] 反射剥离：剥掉页面回显的 payload 自身再比对（回显页布尔漏检根治）
      const tBody = this._stripReflected(String(rTrue?.data ?? ''), truePayload, orig);
      const fBody = this._stripReflected(String(rFalse?.data ?? ''), falsePayload, orig);

      // [P0-FIX 2026-09-11] WAF 拦截页防线：真/假任一侧被 WAF 拦成拦截页时，差异来自
      // WAF 拦截而非 SQL 执行（waf-real echo 安全对照误报根因，2/2 复现）——本对不算命中。
      if (this._pairPollutedByWafBlock(rTrue, rFalse)) continue;
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
      } else if (ctx.config?.boolStableDiff !== false && similarToBaseline(tBody) && similarToBaseline(fBody) && meaningfulDiff(tBody, fBody)) {
        // 二级判据：组间稳定差异。原判据因「假≈基线」失效时（现代页面差异占比小），
        // 改用真/假组各自内部稳定 + 差异可复现 判定，补足 N 个样本后复用 _stableDiffJudge。
        const n = Math.min(4, Math.max(2, Number(ctx.config?.boolStableDiffSamples) || 3));
        const tBodies = [tBody];
        const fBodies = [fBody];
        let usable = true;
        for (let s = 1; s < n; s++) {
          const rT = await this.send(httpClient, ctx, this.buildRequest(target, point, truePayload), ctx);
          const rF = await this.send(httpClient, ctx, this.buildRequest(target, point, falsePayload), ctx);
          if (this.unusableOf(rT) || this.unusableOf(rF)) { usable = false; break; }
          tBodies.push(String(rT?.data ?? ''));
          fBodies.push(String(rF?.data ?? ''));
        }
        if (usable) {
          const sd = this._stableDiffJudge(tBodies, fBodies);
          // [P0-FIX 2026-09-11] 反射回显甄别：差异片段=payload 自身被页面回显 → 非注入信号
          if (sd && !this._isReflectedDiff(sd.tSpan, sd.fSpan, truePayload, falsePayload)) {
            result.vulnerable = true;
            result.dbms = dbms;
            result.evidence = `布尔注入确认(组间稳定差异): 真/假响应在差异片段[${this._sdPreview(sd.tSpan)}]vs[${this._sdPreview(sd.fSpan)}]可复现（真组${n}样本一致、假组${n}样本一致；非数值噪声）`;
            result.payloads = [truePayload, falsePayload];
            point.confirmed = true;
            point.technique = 'boolean';
            point.dbms = dbms;
            break;
          }
        }
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
    // [FIX 2026-09-21 失败样本污染] 两条要求必须同时满足，缺一不可：
    //
    // ① **失败/超时样本必须剔除**：`_bodyOf` 对失败项返回 ''（空串）。空串混进 baselines 后，
    //   `dynamicBlockFilter` 拿它跟每个正常响应两两比对 —— 空串没有任何块，于是**每一块**
    //   都与它不同 → 所有块 diffCount 被整体抬高 → `diffCount[k]/pairs > 0.5` 把**全部块**
    //   判成动态块 → buildDynamicSimilarFn 里 `total === 0` 直接 return true →
    //   **真/假一律判"相似"** → boolean 系统性漏报。
    //
    // ② **只剔除不重试同样会失败**：`dynamicBlockFilter` 在 `baselines.length < 2` 时返回空
    //   动态块集 → 回落到不带动态块排除的严格比对 → 噪声页上真值也≠基线 → 依然漏报。
    //   （这一条是我先只做剔除、被单测直接打脸后补上的 —— 剔除必须配补足。）
    //
    // 实测形态：CI 上 `real-mysql-lab` 的 noisy 场景 `检出=[time] miss=[boolean]` ——
    // 慢机器上并发失败率升高，正踩在这条链上（本地 2385ms 通过、CI 6241ms 失败）。
    const baselines = [];
    const wanted = Math.max(2, rb.baselineSamples || 2);
    let attempt = 0;
    const maxAttempts = 3; // 兜底上限：目标持续不可达时不空转
    while (baselines.length < wanted && attempt < maxAttempts) {
      attempt++;
      const need = wanted - baselines.length;
      const reqs = [];
      for (let i = 0; i < need; i++) reqs.push(this.buildRequest(target, point, orig));
      const resps = await this.sendConcurrent(httpClient, ctx, reqs, {}, concurrency);
      let got = 0;
      for (const r of resps) {
        if (!r || r.__error || !r.resp) continue; // 失败样本：宁可少一个，也不用一个假样本
        const body = this._bodyOf(r);
        if (body) { baselines.push(body); got++; }
      }
      if (got === 0) break; // 整轮全败 → 目标不可达，别继续烧请求
    }
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
      // [P0-FIX 2026-09-11] 反射剥离：剥掉页面回显的 payload 自身再比对（回显页布尔漏检根治；
      // 不回显页面为零操作。multi-engine /num 无 WAF 也 0 检出的根因即回显推离基线）
      const tBodies = resps.slice(0, effSamples).map((r) => this._stripReflected(this._bodyOf(r), truePayload, orig));
      const fBodies = resps.slice(effSamples).map((r) => this._stripReflected(this._bodyOf(r), falsePayload, orig));

      // 三一致率：真≈基线 / 假≠基线 / tBody 与 fBody 有意义差异
      const trueRatio = similarityRate(tBodies, similarToBaseline, true);
      const falseRatio = similarityRate(fBodies, similarToBaseline, false);
      let meaningfulHits = 0;
      for (let s = 0; s < effSamples; s++) {
        // P2-P8 CPU 比对下沉：状态码粗筛——真/假状态不同即视为有意义差异，跳过 body 精细比对
        // content-length 短路（T3）：头长度差异超容差同样跳过 body 全文 LCP/分块比对
        const tRes = resps[s];
        const fRes = resps[effSamples + s];
        // [P0-FIX 2026-09-11] WAF 拦截页防线：任一采样对被拦截页污染 → 该采样不计入命中统计
        // （waf-real echo 安全对照误报根因：WAF 对真/假 payload 拦截差异 ≠ SQL 执行差异）
        if (this._pairPollutedByWafBlock(tRes?.resp, fRes?.resp)) continue;
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
      } else if (ctx.config?.boolStableDiff !== false && similarToBaseline(tBodies[0]) && similarToBaseline(fBodies[0])) {
        // 二级判据：组间稳定差异。仅当「真≈基线 且 假≈基线（但真≠假）」时进入——
        // 这正是 C7 根因场景（差异占比小→假被 _similar 判成≈基线→原判据 `!similarToBaseline(fBody)` 为假）；
        // 若真或假已偏离基线（如 OR-fallback 在非空基线场景），原判据本就能覆盖或本就不应判，不进入稳定差异，零误报。
        // 复用本对已采样的 tBodies/fBodies，零额外请求。
        const sd = this._stableDiffJudge(tBodies, fBodies);
        // [P0-FIX 2026-09-11] 反射回显甄别：差异片段=payload 自身被页面回显 → 非注入信号
        // （waf-real echo 安全对照误报根因：echo 页回显 key=abc AND 1=1/1=2，差异可复现但只是反射）
        if (sd && !this._isReflectedDiff(sd.tSpan, sd.fSpan, truePayload, falsePayload)) {
          result.vulnerable = true;
          result.dbms = dbms;
          result.evidence = `布尔注入确认(组间稳定差异): 真/假响应在差异片段[${this._sdPreview(sd.tSpan)}]vs[${this._sdPreview(sd.fSpan)}]可复现（真组${tBodies.length}样本一致、假组${fBodies.length}样本一致；非数值噪声）`;
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
            stableDiff: { first: sd.first, last: sd.last, tSpan: sd.tSpan, fSpan: sd.fSpan },
          };
          break;
        }
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

  // —— 二级判据：组间稳定差异（[P0-FIX 2026-09-10] 布尔通道系统性漏报根治）——
  // 根因：现代页面真假差异常仅占全文 5~15%（大模板 + 一小块内容差），假值页被 _similar 判成
  // 「≈基线」→ legacy/robust 的「假≠基线」条件恒为假 → 整个布尔通道失效（页面越像越漏报，与真实形态相反）。
  // 改判据不依赖「假≠基线」，而是要求：
  //   ① 真组内部稳定（每个真样本在差异片段处内容一致）
  //   ② 假组内部稳定（每个假样本在差异片段处内容一致）
  //   ③ 真/假差异片段可复现（所有真样本一致、所有假样本一致，且二者不同）
  // 随机 nonce/时间戳因组内不自相似（每次 nonce 不同）→ ①② 证伪 → 排除，误报率保持 0；
  // 差异片段本身是 8+ 位数字（时间戳/计数器）则按 numericNormalized 判无效（动态噪声过滤，保留短数字真实信号）。
  // 仅当原判据失效且真/假确有差异时进入（不放宽进入条件、不改原判定逻辑，零回归）。
  // @param {string[]} tBodies 真条件响应体样本（≥1；robust 复用已采样数组，legacy 补足到 N）
  // @param {string[]} fBodies 假条件响应体样本（≥1）
  // @returns {{first:number,last:number,tSpan:string,fSpan:string}|null} 命中返回差异片段信息，否则 null
  _stableDiffJudge(tBodies, fBodies) {
    if (!tBodies || !fBodies || tBodies.length === 0 || fBodies.length === 0) return null;
    const t0 = tBodies[0];
    const f0 = fBodies[0];
    const span = this._diffSpan(t0, f0);
    if (!span) return null; // 无差异（原判定已拦 meaningfulDiff；此处兜底）
    const { first, last } = span;
    const tSpan = t0.slice(first, last);
    const fSpan = f0.slice(first, last);
    if (tSpan === fSpan) return null; // 差异片段相同 → 无信号
    // ① 真组内部稳定：每个真样本在差异片段处内容一致
    for (const ti of tBodies) {
      if (ti.slice(first, last) !== tSpan) return null;
    }
    // ② 假组内部稳定：每个假样本在差异片段处内容一致
    for (const fi of fBodies) {
      if (fi.slice(first, last) !== fSpan) return null;
    }
    // ③ 动态噪声过滤：差异仅由 8+ 位数字（时间戳/计数器）构成则判无效
    if (numericNormalized(t0) === numericNormalized(f0)) return null;
    return { first, last, tSpan, fSpan };
  }

  /**
   * [P0-FIX 2026-09-11] 反射回显甄别：差异片段若来自「页面把注入值原样回显」，
   * 不构成注入证据（waf-real echo 安全对照误报根因，请求级追踪 2/2 复现）。
   * 机理：echo 类页面把参数值渲染进响应（key = <value>），真/假 payload（如
   * `abc AND 1=1` vs `abc AND 1=2`）都被放行时，唯一差异就是回显的 payload 自身——
   * 组间稳定差异三条件全满足（差异可复现、组内一致、非数值噪声），但它只是反射。
   * 判据（保守，只杀确定形态）：真/假差异片段各自「出现在对方 payload 的回显里」——
   * 即 tSpan 是 truePayload 的（去空格）子串且 fSpan 是 falsePayload 的子串。
   * SQL 执行差异（如行数变化导致的表格/文案差异）不会恰好等于 payload 文本本身。
   * @param {string} tSpan 真组差异片段
   * @param {string} fSpan 假组差异片段
   * @param {string} truePayload
   * @param {string} falsePayload
   * @returns {boolean} true = 反射回显（该对应跳过）
   */
  _isReflectedDiff(tSpan, fSpan, truePayload, falsePayload) {
    if (!tSpan || !fSpan || !truePayload || !falsePayload) return false;
    const norm = (s) => String(s).replace(/\s+/g, '');
    const tp = norm(truePayload);
    const fp = norm(falsePayload);
    const ts = norm(tSpan);
    const fs = norm(fSpan);
    if (!ts || !fs) return false;
    return tp.includes(ts) && fp.includes(fs);
  }

  // 两串差异片段起止下标（半开区间 [first, last)）：最长公共前缀之后到最长公共后缀之前。
  // 完全相同（含等长同串）或仅长度不同、无内部内容差异（如 abc vs abcd）返回 null。供稳定差异判据定位「到底差在哪一块」。
  _diffSpan(a, b) {
    const m = Math.min(a.length, b.length);
    let first = 0;
    while (first < m && a[first] === b[first]) first++;
    if (first === m && a.length === b.length) return null; // 完全相同
    let last = m;
    while (last > first && a[last - 1] === b[last - 1]) last--;
    if (first === last) return null; // 仅长度不同、无内部内容差异 → 视为无信号
    return { first, last };
  }

  // 差异片段预览（截断 + 空值占位），供 evidence 展示
  _sdPreview(s, max = 40) {
    const str = String(s == null ? '' : s);
    if (str.length === 0) return '(空)';
    return str.length > max ? `${str.slice(0, max)}…` : str;
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
    // [P1-FIX 2026-09-08] 空串退化防护：一方为空时 m=0，LCP 判定 `0 >= 0*0.85` 恒真
    // → 空响应被判「与任何基线相似」。典型后果：JSON API 的假条件返回 `[]`（2B）与
    // 真条件完整 JSON 无法区分 → 布尔盲注恒漏检。空串只与空串相似。
    if (m === 0) return la === lb;
    let common = 0;
    while (common < m && a[common] === b[common]) common++;
    if (common >= m * 0.85) return true;
    // P1-D4：LCP 不达标时用分块相似率兜底（首部动态内容场景）
    // P1-FIX 2026-09-08：最后兜底「动态数值归一化」——等长且仅数字段不同（秒级时间戳）
    // 时判相似，抑制安全点误报（详见 numericNormalized 注释）。
    if (la === lb && numericNormalized(a) === numericNormalized(b)) return true;
    return chunkSimilarity(a, b) >= 0.85;
  }
}

export default BooleanBlindDetector;

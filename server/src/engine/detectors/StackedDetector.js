import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload } from '../payloads.js';
import { defaults } from '../../config/defaults.js';

// 堆叠注入检测器（第 5 类 Technique）
// 思路：以 `;` 分隔追加独立延迟语句（SLEEP / WAITFOR DELAY / pg_sleep），
// 若连续 N/2 次响应延迟 ≥ 阈值，即证明第二条语句被成功执行（可执行多条语句）。
// 与 TimeBlindDetector 同构，仅 payload 模板以 `;` 追加独立语句、且风险更高（Critical）。
//
// 投放策略：
//   - 已知 DBMS → 仅投放该库专属堆叠模板
//   - DBMS 未知/未识别 → 遍历全部常见库（MySQL/PostgreSQL/SQL Server/SQLite）模板投放
//   - Oracle 标准驱动不支持堆叠查询 → 直接返回未命中，不投放
export class StackedDetector extends Detector {
  constructor() {
    super('stacked');
    // 堆叠注入判定参数（与 TimeBlindDetector 保持一致，便于对齐行为）
    this.sleepSecs = 2; // 触发明显延迟（秒）
    this.timeThresholdMs = defaults.timeThresholdMs; // 时间盲注判定阈值（ms）
    this.samples = defaults.timeBlindSamples; // 稳定采样次数
  }

  /**
   * 解析需要尝试的 DBMS 列表
   * @param {string|null|undefined} dbms 指纹识别出的 DBMS
   * @returns {string[]} 需逐一尝试的 DBMS 列表
   */
  _resolveDbmsList(dbms) {
    if (dbms && dbms !== 'Unknown') {
      if (dbms === 'Oracle') return []; // Oracle 不支持堆叠，跳过
      return [dbms];
    }
    // 未识别：遍历全部已知支持堆叠的库（排除 Oracle）
    return ['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite'];
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'stacked');

    const dbmsList = this._resolveDbmsList(dbms);
    if (dbmsList.length === 0) {
      result.evidence = dbms === 'Oracle' ? 'Oracle 不支持堆叠查询，跳过' : '无可用堆叠模板';
      return result;
    }

    // [2026-09-24] 本行原本还有一层 `ctx.config?.sleepSecs ??` —— 那个键在 defaults / REST 白名单
    // / CLI / 面板**四处都不存在**（全仓零写入点），留着只会让人以为堆叠的 sleep 能单独调。
    // 现统一走 timeBlindSleepSec（`--time-sec` 就是它的入口）：同一个"慢目标要多等"的意图
    // 在时间盲注与堆叠两条通道上终于同一口径。默认值 2 与本检测器原硬编码值相同 ⇒ 零行为变化。
    const sleep = ctx.config?.timeBlindSleepSec ?? this.sleepSecs;
    const thresholdMs = ctx.config?.timeThresholdMs ?? this.timeThresholdMs;
    const samples = Math.min(10, Math.max(1, ctx.config?.timeBlindSamples ?? defaults.timeBlindSamples));
    // 基线超时：用配置值（不加 sleep 余量），基线不应触发延迟
    const baseTimeoutMs = ctx.config?.timeoutMs ?? defaults.timeoutMs;
    const orig = point.originalValue || '1';

    // ★FIX [误报防护] 基线补偿：测无注入基线耗时。
    // 堆叠判定与注释声称的 TimeBlind「同构」但缺了基线对照——固定阈值下，
    // 正常响应 ≥ 阈值的慢站上任意点都会被误报为堆叠注入并强制 Critical 定级。
    // [OPT-FIX 2026-09-08] 基线 3 次并发采样取中位数：单次基线对网络抖动/目标瞬时排队
    // 敏感（一次偶然慢响应 → effectiveThreshold 虚高 → 漏报；一次偶然快响应 → 阈值偏低 →
    // 并发采样排队被误判为延迟命中 → 误报）。中位数对瞬时毛刺稳健，且 sendConcurrent
    // 3 样本并发只花 1 轮 RTT 墙钟。全部失败 → 退化仅用配置阈值（与旧行为一致）。
    const baseSamples = 3;
    const baseReqs = [];
    for (let i = 0; i < baseSamples; i++) baseReqs.push(this.buildRequest(target, point, orig));
    const baseResps = await this.sendConcurrent(httpClient, ctx, baseReqs, { timeoutMs: baseTimeoutMs }, baseSamples);
    const baseElapsed = baseResps
      .filter((r) => !r.__error && r.resp != null)
      .map((r) => r.__elapsed)
      .sort((a, b) => a - b);
    const baselineMs = baseElapsed.length
      ? baseElapsed[Math.floor(baseElapsed.length / 2)] // 中位数
      : 0;
    // 有效阈值：取「配置阈值」与「基线 + 半个预期延迟」的较大者，
    // 保证命中样本的耗时必须显著高于该点自身正常水位，而非仅高于全局常数。
    const effectiveThreshold = Math.max(thresholdMs, baselineMs + (sleep * 1000) / 2);
    // ★FIX [P0]：注入超时 = 有效阈值 + 完整延迟 + 安全余量。
    // 旧实现 timeoutMs 在基线前固定为 baseTimeout + sleep，未补偿 baselineMs →
    // 慢站上注入后耗时（baseline + sleep）超过 timeout → catch → continue →
    // 全部样本被跳过 → 堆叠注入漏报。
    const timeoutMs = effectiveThreshold + sleep * 1000;

    // 逐个 DBMS 尝试；首个命中即确认（避免无谓请求）
    // [B2-FIX] 模板选族 + 单一模板贯穿（对标 TimeBlindDetector 的单模板策略）：
    // 原实现 templates[i % templates.length] 在样本间轮换，字符串上下文目标约一半样本
    // 落在裸拼接模板（`{ORIG}; ...`）→ 语法错误 → stable < ceil(samples/2) → 漏报。
    // 修复：按注入点上下文选族——boundary/orig 含引号 → 自闭合族（`{ORIG}'...`），
    // 否则裸拼接族（`{ORIG};...`）；族内取第一条模板贯穿全部 samples（语法同构，
    // 命中即全命中）。主族全败且存在异族模板时，用异族模板补一轮（防选族误判漏报）。
    const origStr = String(orig);
    const quoteCtx =
      /['"]/.test(String(point.boundary || '')) || !/^[\d.]+$/.test(origStr);
    const pickTemplate = (tpls, quoted) => {
      const fam = quoted
        ? tpls.filter((t) => /^\{ORIG\}'/.test(t))
        : tpls.filter((t) => /^\{ORIG\};/.test(t));
      return fam[0] || tpls[0];
    };
    // 单族采样：全部样本用同一模板，返回 { stable, matchedPayloads }
    // [perf-FIX 2026-09-07] 串行→限并发：原 for 循环逐个 await，samples×(RTT+sleep) 全额累加
    // （默认 5 样本 × 2s sleep ≈ 10s+ 墙钟，e2e stacked 场景实测 6s）。改走基类 sendConcurrent
    // （与 TimeBlindDetector._robustDetect 同一通道）：并发度取 blindRobust.concurrency（默认 4），
    // 墙钟 ≈ ceil(samples/并发)×sleep。语义不变：每样本独立生成 payload（保留 obfuscate/tamper
    // 逐样本语义）、独立计时（__elapsed 优先纯网络耗时）、超时/失败仍计为未触发延迟。
    // [OPT-FIX 2026-09-08] opts.serial=true + samplesOverride：串行复验模式（确认命中前消除
    // 并发排队对计时的干扰），样本数可覆写（复验只发 1 次）。
    const stackedConcurrency = Math.max(
      1,
      Math.min(ctx.config?.blindRobust?.concurrency ?? 4, samples)
    );
    const probeFamily = async (tpl, opts = {}) => {
      const serial = opts.serial === true;
      const n = Math.min(Math.max(1, opts.samplesOverride ?? samples), serial ? 1 : samples);
      const reqs = [];
      const payloads = [];
      for (let i = 0; i < n; i++) {
        const payload = this.obfuscateValue(ctx, fillPayload(tpl, { orig, sleep }));
        payloads.push(payload);
        reqs.push(this.buildRequest(target, point, payload));
      }
      let resps;
      if (serial) {
        // 串行复验：逐个 await，无并发排队干扰，计时可信
        resps = [];
        for (const req of reqs) {
          const t0 = Date.now();
          try {
            const resp = await this.send(httpClient, ctx, req, { timeoutMs });
            resps.push({ resp, __elapsed: resp?.__networkMs ?? (Date.now() - t0) });
          } catch (e) {
            resps.push({ __error: e, __elapsed: Date.now() - t0 });
          }
        }
      } else {
        resps = await this.sendConcurrent(httpClient, ctx, reqs, { timeoutMs }, stackedConcurrency);
      }
      let stable = 0;
      const matchedPayloads = [];
      for (let i = 0; i < n; i++) {
        const r = resps[i] || {};
        if (r.__error || r.resp == null) continue; // 超时/网络错误：未触发延迟
        if (r.__elapsed >= effectiveThreshold) {
          stable++;
          matchedPayloads.push(payloads[i]);
        }
      }
      return { stable, matchedPayloads };
    };

    for (const dbmsKey of dbmsList) {
      const templates = (PAYLOADS[dbmsKey] && PAYLOADS[dbmsKey].stacked) || [];
      if (!templates.length) continue; // 该库无堆叠模板（如 Oracle）

      const tpl = pickTemplate(templates, quoteCtx);
      let { stable, matchedPayloads } = await probeFamily(tpl);
      // 主族零命中且存在异族模板 → 用异族模板补一轮（选族误判兜底）
      if (stable === 0) {
        const altTpl = pickTemplate(templates, !quoteCtx);
        if (altTpl !== tpl) {
          const alt = await probeFamily(altTpl);
          stable = alt.stable;
          matchedPayloads = alt.matchedPayloads;
        }
      }

      if (stable >= Math.ceil(samples / 2)) {
        // [OPT-FIX 2026-09-08] 串行复验（防并发排队误报）：并发采样时 N 个请求可能被目标
        // 连接池/应用排队同时拖慢，elapsed 达标但非真实延迟。复验用同模板串行发 1 次——
        // 无排队干扰下若仍延迟达标，确认注入；复验未达标（视为偶发排队）→ 降级不计命中，
        // 继续尝试其余库。复验失败不消耗该库的命中计数（stable 已达半数，仅此一轮作废）。
        const reverify = await probeFamily(tpl, { serial: true, samplesOverride: 1 });
        if (reverify.stable < 1) {
          continue; // 复验未通过：偶发排队，不确认，尝试下一个 DBMS
        }
        result.vulnerable = true;
        result.dbms = dbmsKey;
        result.evidence =
          `堆叠注入确认：${dbmsKey} 连续 ${stable}/${samples} 次响应延迟 ≥ ${Math.round(effectiveThreshold)}ms` +
          `（基线 ${Math.round(baselineMs)}ms + 配置阈值 ${thresholdMs}ms 补偿），` +
          `';' 后第二条语句被成功执行（可执行多条语句）`;
        result.payloads = matchedPayloads;
        // 标记注入点已确认（与经典检测器一致，便于报告/进度展示）
        point.confirmed = true;
        point.technique = 'stacked';
        point.dbms = dbmsKey;
        return result;
      }
    }

    return result;
  }
}

export default StackedDetector;

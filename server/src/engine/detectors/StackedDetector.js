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

    const sleep = ctx.config?.sleepSecs ?? this.sleepSecs;
    const thresholdMs = ctx.config?.timeThresholdMs ?? this.timeThresholdMs;
    const samples = Math.min(10, Math.max(1, ctx.config?.timeBlindSamples ?? defaults.timeBlindSamples));
    // 基线超时：用配置值（不加 sleep 余量），基线不应触发延迟
    const baseTimeoutMs = ctx.config?.timeoutMs ?? defaults.timeoutMs;
    const orig = point.originalValue || '1';

    // ★FIX [误报防护] 基线补偿：先测一次无注入基线耗时。
    // 堆叠判定与注释声称的 TimeBlind「同构」但缺了基线对照——固定阈值下，
    // 正常响应 ≥ 阈值的慢站上任意点都会被误报为堆叠注入并强制 Critical 定级。
    const baseStart = Date.now();
    try {
      await this.send(httpClient, ctx, this.buildRequest(target, point, orig), { timeoutMs: baseTimeoutMs });
    } catch { /* 基线失败不阻断，退化为仅用配置阈值 */ }
    const baselineMs = Date.now() - baseStart;
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
    const probeFamily = async (tpl) => {
      let stable = 0;
      const matchedPayloads = [];
      for (let i = 0; i < samples; i++) {
        const payload = this.obfuscateValue(ctx, fillPayload(tpl, { orig, sleep }));
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
        const elapsed = Date.now() - start;
        if (res && elapsed >= effectiveThreshold) {
          stable++;
          matchedPayloads.push(payload);
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

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
    const samples = this.samples;
    // 放宽超时，避免把正常延迟误判为超时（基础超时 + 单条延迟余量）
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleep * 1000;
    const orig = point.originalValue || '1';

    // 逐个 DBMS 尝试；首个命中即确认（避免无谓请求）
    for (const dbmsKey of dbmsList) {
      const templates = (PAYLOADS[dbmsKey] && PAYLOADS[dbmsKey].stacked) || [];
      if (!templates.length) continue; // 该库无堆叠模板（如 Oracle）

      let stable = 0;
      const matchedPayloads = [];
      for (let i = 0; i < samples; i++) {
        const tpl = templates[i % templates.length];
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
        if (res && elapsed >= thresholdMs) {
          stable++;
          matchedPayloads.push(payload);
        }
      }

      if (stable >= Math.ceil(samples / 2)) {
        result.vulnerable = true;
        result.dbms = dbmsKey;
        result.evidence =
          `堆叠注入确认：${dbmsKey} 连续 ${stable}/${samples} 次响应延迟 ≥ ${thresholdMs}ms，` +
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

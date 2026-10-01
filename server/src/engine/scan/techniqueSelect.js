// =====================================================================
// techniqueSelect.js — 技术位选择：_selectedTechs（白名单 + knownPoint 交集 + risk 门控）
// 与 activeDetectors（唯一检测器过滤入口）。
// 自 ScanManager.js 拆出（纯搬移）：由 ScanManager.prototype 挂载（this 语义不变）。
// =====================================================================
import { TECHNIQUE_TYPES } from '../payloads.js';

  // 选中技术集合：空/未定义 → 全部（含 stacked）；否则按所选
  // 若配置了 risk 级别，缩减高风险技术：
  //   risk 1：仅 union/error/boolean（安全，无写请求/无长时间等待）
  //   risk 2：全部（含 time/stacked/oob，默认）
  //   risk 3：全部 + 额外 OR 变体（由 Detector 层消费 risk 字段）
export function _selectedTechs(config) {
    const sel = config && config.techniques;
    let techs = sel && sel.length ? sel : TECHNIQUE_TYPES;
    // [P0 2026-09-09] knownPoint.techniques：已知注入点的技术位白名单（扫描级过滤，
    // 与 config.techniques 取交集）——手工确认 union 注入后不再全技术位扫
    const kpTechs = config && config.knownPoint && Array.isArray(config.knownPoint.techniques)
      ? config.knownPoint.techniques
      : null;
    if (kpTechs && kpTechs.length) techs = techs.filter((t) => kpTechs.includes(t));
    // risk 门控
    const risk = (config && config.risk) != null ? config.risk : 2;
    if (risk < 2) {
      // risk 1：排除 time（慢速等待）、stacked（写操作风险）、oob（出站请求）
      techs = techs.filter((t) => !['time', 'stacked', 'oob'].includes(t));
    }
    // risk 3 不需要额外过滤，因为 risk 3 的 OR 变体由 Detector 独立消费 risk 字段
    return techs;
  }

  // 按技术选择过滤检测器（唯一过滤入口）
export function activeDetectors(config) {
    const sel = this._selectedTechs(config);
    return this.detectors.filter((d) => sel.includes(d.technique));
  }

// =====================================================================
// strategyOrder.js — 编排总图：检测器优先级、阶段与降级去向的单一事实源
//
// [2026-11-06 编排总图] 此前顺序散在 ScanManager 构造函数的数组 + 三处「独立实例」
// 注释里，读调用链要跳多处。本表把「谁先跑、谁是补充趟、谁末位兜底」写在一处，
// 并由 arch-guard 的顺序 / 类存在性 / phase 判据钉住，防止代码与图漂移。
//
// ⚠️ 本表只负责编排描述与实例生成，**不参与技术位过滤**：
//    运行时过滤仍走 scan/techniqueSelect.js 的 activeDetectors(config)，
//    依据是 detector.technique，不是本表的 technique 字段。
//    phase 语义：primary=一阶主循环；primary-optin=一阶但默认不勾选；
//    supplemental=聚合后补充趟，不进一阶 per-point 循环。
//    layer 语义（[D257]）：一阶调度层，fast=快速回显/布尔层，slow=慢速采样层；
//    supplemental 不参与一阶调度，故不填 layer。detect.js 的 FAST/SLOW **只能**由本表派生，
//    不许再写第二份数组 —— 否则「表里有、调度里没有」的检测器会静默不跑。
// =====================================================================
import { UnionDetector } from '../detectors/UnionDetector.js';
import { ErrorDetector } from '../detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../detectors/TimeBlindDetector.js';
import { StackedDetector } from '../detectors/StackedDetector.js';
import { OobDetector } from '../detectors/OobDetector.js';
import { InlineQueryDetector } from '../detectors/InlineQueryDetector.js';
import { SecondOrderDetector } from '../detectors/SecondOrderDetector.js';
import { NoSqlInjectionDetector } from '../detectors/NoSqlInjectionDetector.js';

export const STRATEGY_ORDER = [
  { technique: 'union', Detector: UnionDetector, phase: 'primary', layer: 'fast', fallbackTo: 'error', note: '回显最快，先试' },
  { technique: 'error', Detector: ErrorDetector, phase: 'primary', layer: 'fast', fallbackTo: 'boolean', note: '报错回显' },
  { technique: 'boolean', Detector: BooleanBlindDetector, phase: 'primary', layer: 'fast', fallbackTo: 'time', note: '真假差分' },
  { technique: 'time', Detector: TimeBlindDetector, phase: 'primary', layer: 'slow', fallbackTo: 'stacked', note: '延时盲注' },
  { technique: 'stacked', Detector: StackedDetector, phase: 'primary', layer: 'slow', fallbackTo: 'oob', note: '堆叠查询' },
  { technique: 'oob', Detector: OobDetector, phase: 'primary', layer: 'slow', fallbackTo: null, note: '末位兜底：盲注 / 无回显' },
  { technique: 'inline', Detector: InlineQueryDetector, phase: 'primary-optin', layer: 'fast', fallbackTo: null, note: '对标 sqlmap -Q；默认 techniques 不含，避免无回显目标噪音' },
  { technique: 'second_order', Detector: SecondOrderDetector, phase: 'supplemental', fallbackTo: null, note: '聚合后 _runSecondOrder 补充趟，与一阶流水线正交' },
  { technique: 'nosql', Detector: NoSqlInjectionDetector, phase: 'supplemental', fallbackTo: null, note: 'opt-in，_runNoSql 补充趟（NoSQL / GraphQL / SSTI）' },
];

/**
 * 取某一调度层的一阶技术位（[D257] 由编排总图派生，禁止另写一份）。
 * @param {'fast'|'slow'} layer 调度层
 * @returns {string[]} 该层技术位（按表内顺序）
 */
function techniquesInLayer(layer) {
  return STRATEGY_ORDER.filter((e) => e.layer === layer).map((e) => e.technique);
}

/** 快速层：回显/布尔类，命中即典型注入（[D257] 派生值，改表即改调度）。 */
export const FAST_TECHNIQUES = Object.freeze(techniquesInLayer('fast'));

/** 慢速采样层：time/stacked/oob，彼此无依赖，层内并行。 */
export const SLOW_TECHNIQUES = Object.freeze(techniquesInLayer('slow'));

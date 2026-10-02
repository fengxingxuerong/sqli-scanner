// ============================================================================
// scanPresets.ts —— 扫描预设（quick / standard / deep，2026-10-02 竞品吸收批次）
//
// 竞品对标：ZAP 的 Attack Strength / sqlmap 的 --level/--risk 是「一次旋钮调一整束
// 参数」的组合；本仓此前只有逐项滑杆，新用户想「先快跑一遍再深扫」要手动拨 5+ 个
// 控件。预设 = 一组**既有键**的 patch 快照，不引入任何新配置键（后端零改动、契约
// 测试天然覆盖：预设里的每个键都必须已在 SCAN_CONFIG_KEYS + SCAN_CONFIG_VALUE_TYPES
// 里，src/tests/scanPresets.test.ts 钉死）。
//
// 语义：预设是 **patch（部分覆盖）** 而不是整份配置 —— 应用 quick 不会把用户手填的
// proxy/scope/extractScope 等键重置掉，只覆盖预设声明的键。
// 刻意**不**纳入 paramMine：挖掘会向目标发额外探测请求，属显式 opt-in 能力，
// 不该被「点个预设」顺带打开。
// ============================================================================

import type { ScanConfig, TechniqueType } from './types';

export type ScanPresetId = 'quick' | 'standard' | 'deep';

export interface ScanPreset {
  id: ScanPresetId;
  /** i18n key（scanConfig.presetQuick / presetStandard / presetDeep） */
  labelKey: string;
  hintKey: string;
  patch: Partial<ScanConfig>;
}

const STANDARD_TECHNIQUES: TechniqueType[] = ['union', 'error', 'boolean', 'time', 'stacked'];
const QUICK_TECHNIQUES: TechniqueType[] = ['union', 'error'];
const DEEP_TECHNIQUES: TechniqueType[] = [...STANDARD_TECHNIQUES, 'inline'];

export const SCAN_PRESETS: readonly ScanPreset[] = [
  {
    id: 'quick',
    labelKey: 'scanConfig.presetQuick',
    hintKey: 'scanConfig.presetQuickHint',
    // 快速面检：只跑响应快的两类技术（union/error），不开爬虫，预筛全开压请求量
    patch: {
      level: 1,
      risk: 1,
      techniques: QUICK_TECHNIQUES,
      crawlDepth: 0,
      crawlForms: false,
      prefilter: true,
      skipStatic: true,
    },
  },
  {
    id: 'standard',
    labelKey: 'scanConfig.presetStandard',
    hintKey: 'scanConfig.presetStandardHint',
    // 标准扫描 = DEFAULT_CONFIG 的检测强度面（level/risk 与后端 defaults 对齐）
    patch: {
      level: 1,
      risk: 1,
      techniques: STANDARD_TECHNIQUES,
      crawlDepth: 1,
      prefilter: true,
      skipStatic: false,
    },
  },
  {
    id: 'deep',
    labelKey: 'scanConfig.presetDeep',
    hintKey: 'scanConfig.presetDeepHint',
    // 深度审计：sqlmap 上限强度 + 全技术（含 inline Q）+ 爬虫 + 表单 + 关预筛（宁可慢不可漏）
    patch: {
      level: 5,
      risk: 3,
      techniques: DEEP_TECHNIQUES,
      crawlDepth: 2,
      crawlForms: true,
      prefilter: false,
      skipStatic: false,
      testHeaders: true,
    },
  },
];

/** 按 id 取预设（未知 id 返回 undefined，调用方无需先校验） */
export function getScanPreset(id: ScanPresetId): ScanPreset | undefined {
  return SCAN_PRESETS.find((p) => p.id === id);
}

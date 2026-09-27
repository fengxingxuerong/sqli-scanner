// ============================================================================
// sectionProps.ts —— ScanConfigPanel 分段组件的统一 props 契约（2026-09-27 拆分）
// 每个分段只依赖 config + onChange（渲染所需的其它数据以扩展接口传入）。
// ============================================================================
import type { ScanConfig, WafSuggestion } from '../../shared/types';

export type OnPatch = (patch: Partial<ScanConfig>) => void;

export interface ScanConfigSectionProps {
  config: ScanConfig;
  onChange: OnPatch;
}

/** WAF 绕过分段额外携带主面板透传的 tamper 推荐结果 */
export interface WafSectionProps extends ScanConfigSectionProps {
  wafSuggestion?: WafSuggestion[];
}

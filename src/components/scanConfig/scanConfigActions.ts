// ============================================================================
// scanConfigActions.ts —— ScanConfigPanel 各分段的变更处理器（2026-09-27 拆分）
// 原实现全部内联在 ScanConfigPanel（1055 行上帝组件）里；现集中到本文件，
// 各分段组件通过 createScanConfigActions(config, onChange) 取用。
// 只搬结构不改行为：每个 handler 的判据注释随代码迁移、逐字保留。
// ============================================================================
import type { ChangeEvent } from 'react';
import type { ScanConfig, ExtractScopeConfig } from '../../shared/types';
import { parseScopeList } from '../../shared/scanConfig';
import type { ExtractScopeField } from '../../shared/constants';

type OnPatch = (patch: Partial<ScanConfig>) => void;

/**
 * 面板变更处理器工厂。刻意不用 use 前缀：内部无任何 Hook，是纯闭包工厂，
 * 每个分段组件在自己的顶部各取所需地解构。
 */
export function createScanConfigActions(config: ScanConfig, onChange: OnPatch) {
  const handleToggle = (key: keyof ScanConfig) => (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ [key]: e.target.checked });
  };

  const handleNumber = (key: keyof ScanConfig) => (_: Event, val: number | number[]) => {
    onChange({ [key]: val as number });
  };

  // [2026-10-03 UI-REACH] 整数型调优键的文本输入处理器（拖库行数/并发族、时间盲注采样与
  // sleep 族）。空串/非法 ⇒ 删键（undefined = 引擎走默认兜底，与「关闭态请求体省键」的
  // 全局口径一致）；数字原样上送 —— 范围由后端 scalarsCore 的 pickInt clamp 把守，
  // 前端不复制上限逻辑以免两处漂移（min/max 只出现在 <input> 上做输入提示）。
  const handleIntInput = (key: keyof ScanConfig) => (e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value.trim();
    const n = Number(v);
    onChange({ [key]: v === '' || !Number.isFinite(n) ? undefined : Math.floor(n) } as Partial<ScanConfig>);
  };

  // [P0-FIX 2026-09-09] 字符串型配置键统一走这里（matchString / notString / testFilter / testSkip）。
  // 这些键在后端是**字符串**（Detector.matchAnchors 用 text.includes()、payloadRegistry 用子串匹配），
  // 用布尔开关表达 = 勾了但传了错的类型，引擎侧静默按「真页含 'true'」这种荒谬规则跑。
  // 空串 → undefined：关闭态在请求体里干脆地没这个键，而不是发个 '' 让后端去猜。
  const handleText = (key: keyof ScanConfig) => (e: ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value.trim();
    onChange({ [key]: v === '' ? undefined : v } as Partial<ScanConfig>);
  };

  // [2026-09-26] matchCode（对标 --code）是**对象**形态 { true, false }（100-599 的期望状态码）。
  // 两侧都空 = 不启用 → 整个键从请求体省略（与其它锚点「关闭态不留空值」同口径）。
  // 只填一侧是合法的（后端 clampInt 逐侧校验，单侧期望同样能当判据）。
  const setMatchCode = (side: 'true' | 'false', raw: string) => {
    const n = Number(String(raw).trim());
    const cur = { ...(config.matchCode ?? {}) } as { true?: number; false?: number };
    if (raw.trim() === '' || !Number.isFinite(n)) delete cur[side];
    else cur[side] = Math.floor(n);
    onChange({ matchCode: Object.keys(cur).length ? cur : undefined });
  };

  // [2026-09-23 E2] 枚举动作的子字段更新：undefined 一律**删键**（而不是留个空值），
  // 与其它配置「关闭态在请求体里干脆地没这个键」口径一致 —— 后端 sanitizeExtractScope
  // 也是按「有值才写入」处理，两侧不会出现「有键无值」的中间态。
  const setScopeField = (key: ExtractScopeField | 'excludeSysdbs', value: unknown) => {
    const cur = config.extractScope;
    if (!cur) return;
    const next = { ...cur } as Record<string, unknown>;
    if (value === undefined) delete next[key];
    else next[key] = value;
    onChange({ extractScope: next as unknown as ExtractScopeConfig });
  };

  // 授权范围：多行/逗号（或分号）分隔 → string[]；留空 = 不启用（发 undefined，后端零行为变化）
  const handleScopeChange = (raw: string) => {
    const list = parseScopeList(raw);
    onChange({ scope: list.length ? list : undefined });
  };

  // [2026-09-23 UI-REACH] 嵌套对象配置（noSql / oob / secondOrder）的子字段更新。
  // 与 setScopeField 同口径：undefined 一律**删键**（关闭态在请求体里干脆地没这个键）。
  // 刻意**不**在此自动打开 enabled —— OOB 会向回调地址发起出站回连、二阶会发出真实写请求，
  // 「填了地址就自动生效」会把两个有副作用的动作变成隐蔽副作用，总开关必须由用户显式打开。
  const patchNested = (key: 'noSql' | 'oob' | 'secondOrder', field: string, value: unknown) => {
    const cur = (config[key] ?? {}) as Record<string, unknown>;
    const next: Record<string, unknown> = { ...cur };
    if (value === undefined) delete next[field];
    else next[field] = value;
    onChange({ [key]: next } as unknown as Partial<ScanConfig>);
  };

  return {
    handleToggle, handleNumber, handleIntInput, handleText, setMatchCode,
    setScopeField, handleScopeChange, patchNested,
  };
}

export type ScanConfigActions = ReturnType<typeof createScanConfigActions>;

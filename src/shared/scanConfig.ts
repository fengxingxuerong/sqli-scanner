// [P0-FIX 2026-09-09] /api/scan/start 的 config 构造层（前端侧契约的唯一实现点）
//
// 为什么单独成文件（实战后果）：
//   后端 sanitizeStart 只认 KNOWN_CFG_KEYS 白名单，白名单外的键 `logger.debug` 一句就丢了；
//   而「面板写了开关、请求体里没有那个键」这类断链已经在本项目连续出现三批——每一次都是靠人
//   记住「新开关要接进 startScan」。这里把「面板键 → 请求体键」的映射收敛成一个纯函数，
//   由 src/shared/constants.ts 的 SCAN_CONFIG_KEYS 驱动，并由 scanConfig.contract.test.ts 钉死：
//   面板能改的键必然进请求体；进请求体的键必然在后端白名单内；类型与后端解析口径一致。
import { SCAN_CONFIG_KEYS, SCAN_CONFIG_VALUE_TYPES } from './constants';
import type { ScanConfigKey } from './constants';
import type { ScanConfig } from './types';

/** 授权范围输入解析：多行 / 逗号 / 分号分隔 → string[]（空条目剔除，留空 = 不启用） */
export function parseScopeList(raw: string): string[] {
  return String(raw ?? '')
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * 按键声明的类型归一化。返回 undefined = 该键从请求体省略（关闭态干净，不污染配置）。
 * 关键点：**不允许「勾了但传了错的类型」**。例如 matchString 在后端是字符串
 * （Detector.matchAnchors 走 text.includes(...)），若前端把它当布尔开关发 true，
 * 判定就变成「真页必须包含字符 'true'」，在强动态页面上静默失效。
 */
function normalizeScanValue(key: ScanConfigKey, value: unknown): unknown {
  const type = SCAN_CONFIG_VALUE_TYPES[key];
  switch (type) {
    case 'boolean':
      if (typeof value === 'boolean') return value;
      if (value === 'true' || value === 1) return true;
      if (value === 'false' || value === 0) return false;
      return undefined;
    case 'number': {
      if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
      if (typeof value === 'string' && value.trim() !== '') {
        const n = Number(value);
        return Number.isFinite(n) ? n : undefined;
      }
      return undefined;
    }
    case 'string': {
      if (value === null || value === undefined) return undefined;
      const s = String(value).trim();
      return s === '' ? undefined : s;
    }
    case 'stringOrNull': {
      if (value === null || value === undefined) return null;
      const s = String(value).trim();
      return s === '' ? null : s;
    }
    case 'stringArray': {
      if (Array.isArray(value)) return value.filter((x) => typeof x === 'string' && x.trim() !== '');
      // 容错：调用方（CLI / 历史快照）可能给逗号串，后端同源解析，这里对齐成数组
      if (typeof value === 'string') return parseScopeList(value);
      return undefined;
    }
    case 'object':
    default:
      // auth / noSql / wafEvasion：整体原样透传，子字段由后端逐项 clamp；非标量垃圾形态丢弃
      if (value === null || value === undefined) return value === null ? null : undefined;
      return typeof value === 'object' ? value : undefined;
  }
}

/**
 * 构造 /api/scan/start 的 `config`（内置引擎）。
 *
 * 两步语义，缺一不可：
 *  ① 结构化透传**全部**入参键（不手抄字段表）：历史快照 / 后端回显里带着前端未建模的键
 *     （delay、reqRate、blindRobust、oob、secondOrder、excludeSysdbs…）。逐个字段手抄正是
 *     「续跑丢 scope」这类事故的根源——这里保证：前端没建模也照样传回去。
 *  ② 再按 SCAN_CONFIG_KEYS 逐键归一化落位（类型对齐 + 空串/undefined 省略），保证面板键
 *     一定出现在请求体里，且形态是后端认的形态。
 */
export function buildStartConfig(config?: Partial<ScanConfig> | null): Record<string, unknown> {
  const src = (config && typeof config === 'object' ? config : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    if (v !== undefined) out[k] = v;
  }
  for (const key of SCAN_CONFIG_KEYS) {
    if (!(key in src)) continue;
    const normalized = normalizeScanValue(key, src[key]);
    if (normalized === undefined) delete out[key];
    else out[key] = normalized;
  }
  return out;
}

/**
 * 从历史 / 报告的完整配置构造续跑 config（结构化透传 + 会话文件名回退）。
 *
 * 为什么必须有这个函数（[P0-SEC] 授权范围）：上一轮加的 scope 硬约束是「渗透第一红线」，
 * 若「从历史续扫」这条最常见的路径把 scope 漏掉，就等于一次**无限制**的开火。手抄字段表迟早
 * 漏一个键，所以这里只做「整体浅拷贝 + 显式会话回退」，不逐字段列举。
 * @param saved 历史快照里的 report.target.config（可能缺失/为 null）
 * @param patch 续跑对话框里的即时覆写（目前只有 scope）
 */
export function buildResumeConfig(
  saved?: Partial<ScanConfig> | null,
  patch?: Partial<ScanConfig>
): ScanConfig {
  const src = (saved && typeof saved === 'object' ? saved : {}) as Record<string, unknown>;
  const next: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    if (v !== undefined) next[k] = v;
  }
  for (const [k, v] of Object.entries(patch || {})) {
    if (v !== undefined) next[k] = v;
    else delete next[k];
  }
  // 会话文件名回退：只开了「断点续跑」而未落显式文件名时，用后端默认会话名
  // （next 是开放键集合，需经 unknown 中转断言为 ScanConfig：直接断言 TS 会拒）
  const cfg = next as unknown as ScanConfig;
  if (!cfg.sessionFile && cfg.sessionDefault) next.sessionFile = 'sqli-session-latest.json';
  // 去掉 undefined，避免请求体里出现「有键无值」的噪声
  for (const k of Object.keys(next)) if (next[k] === undefined) delete next[k];
  return next as unknown as ScanConfig;
}

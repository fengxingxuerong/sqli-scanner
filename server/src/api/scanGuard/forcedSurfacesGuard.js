// ============================================================================
// forcedSurfacesGuard.js —— [D202] 强制面四键的 REST 入口（独立模块）
//
// 抽成独立文件有两个原因：
//   ① scalarsEgress.js 与 scalarsCore.js 有一段存量近似代码，令牌窗口贴着
//      duplication-guard 基线（只减不增）——本函数若写进 scalarsEgress 会让
//      窗口对齐多出 4 个重复块（实测 3225→3229）；
//   ② 校验规则单源在 src/config/forcedSurfaces.js（已抛 AppError），这里保留
//      同码值包装作 REST 边界，与 CLI 的 buildConfig 共用同一份判定。
// ============================================================================
import { ErrorCode, AppError } from '../../core/errors.js';
import { FORCED_SURFACE_KEYS, normalizeForcedSurface } from '../../config/forcedSurfaces.js';

/**
 * @param {object} config 落地目标
 * @param {object} cfg 原始入参
 * @returns {void}
 */
export function applyForcedSurfacesGuarded(config, cfg) {
  for (const key of FORCED_SURFACE_KEYS) {
    const v = cfg[key];
    if (v === undefined || v === null || v === '') continue;
    try {
      config[key] = normalizeForcedSurface(key, v);
    } catch (e) {
      throw new AppError(ErrorCode.INVALID_PARAM, e.message);
    }
  }
}

// ============================================================================
// forcedSurfaces.js —— [D202] 强制面四键的**单源校验**
//
// CLI（buildConfig）与 REST（sanitizeStart）必须给出同一份判定：两处各写一份正则/枚举
// 会静默分叉（本仓反复栽过的形态），也会让 duplication-guard 的重复块计数只增不减。
// 本模块只做「归一化或拒绝」，统一抛 AppError(INVALID_PARAM)；REST 侧保留包装作边界。
// 不用裸 Error：error-contract-guard 的非受限目录「只减不增」会把新增文件的 5 处裸
// Error 判成新债（该门禁只在 pre-commit 跑，收口清单里没有，见 CHANGELOG D202）。
// 每个键一个独立小校验器：主函数圈复杂度不因新增键上涨（新代码硬上限 15）。
// ============================================================================
import { ErrorCode, AppError } from '../core/errors.js';

export const FORCED_SURFACE_KEYS = Object.freeze(['os', 'encoding', 'charset', 'fingerprint']);
const OS_VALUES = ['windows', 'linux'];
const ENCODING_RE = /^[a-z0-9][a-z0-9._:+-]*$/i;
const MAX_ENCODING_LEN = 30;
const MAX_CHARSET_LEN = 256;

/** @type {Record<string, (v: unknown) => string|boolean>} */
const VALIDATORS = {
  os: (v) => {
    if (typeof v !== 'string' || !OS_VALUES.includes(v.toLowerCase())) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'os 仅支持 windows | linux');
    }
    return v.toLowerCase();
  },
  encoding: (v) => {
    if (typeof v !== 'string' || v.length > MAX_ENCODING_LEN || !ENCODING_RE.test(v)) {
      throw new AppError(ErrorCode.INVALID_PARAM, `encoding 仅支持 ≤${MAX_ENCODING_LEN} 字符的字符集标签`);
    }
    return v;
  },
  charset: (v) => {
    if (typeof v !== 'string' || v.length > MAX_CHARSET_LEN || /[\r\n\0]/.test(v)) {
      throw new AppError(ErrorCode.INVALID_PARAM, `charset 仅支持 ≤${MAX_CHARSET_LEN} 字符且不含换行/NUL`);
    }
    return v;
  },
  fingerprint: (v) => {
    if (typeof v !== 'boolean') throw new AppError(ErrorCode.INVALID_PARAM, 'fingerprint 仅支持布尔值');
    return v;
  },
};

/**
 * @param {string} key os | encoding | charset | fingerprint
 * @param {unknown} value
 * @returns {string|boolean|undefined} 归一化后的值；未配置返回 undefined
 * @throws {AppError} 形状/枚举不合法（ErrorCode.INVALID_PARAM）
 */
export function normalizeForcedSurface(key, value) {
  if (value === undefined || value === null || value === '') return undefined;
  const validate = VALIDATORS[key];
  if (!validate) throw new AppError(ErrorCode.INVALID_PARAM, `未知强制面键：${key}`);
  return validate(value);
}

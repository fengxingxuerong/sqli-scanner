// =====================================================================
// scanConfigUtils.js —— REST/CLI 配置入口的**值消毒原语**
//
// [大文件拆分 2026-09-21] 从 api/scanRoutes.js 抽出（原 26–65 行的 clamp 家族
// + 704–717 行的 clampParams）。
//
// 为什么单独成模块（不只是行数）：
//   1. 这 8 个函数是**纯函数**：无 I/O、无状态、不依赖任何模块级常量。
//      此前只能通过「构造一份 body 调 sanitizeStart」间接验证，现在可穷举边界。
//   2. 它们是配置入口的第一道闸门：clampInt/clampNum 决定数值区间、
//      clampStr 决定长度上限、sanitizeCookieMap 决定原型污染键能否进来。
//      抽出来后每条闸门都能单独钉住（见 tests/scanConfigUtils.test.js）。
//   3. 依赖方向：本模块是叶子（零 import），被 scanRoutes.js 单向引用。
//
// 职责边界：只做「单个值 → 合法值/undefined」。
// **不做**键名白名单判定（那是 KNOWN_CFG_KEYS 的事）、不做跨字段校验。
// 返回 `undefined` 表示「该键不应写入」，与 `sanitizeStart` 的省略语义一致
// —— 不要为了"给个默认值"擅自改成返回 def（会让下游无法区分「未传」与「传了非法值」）。
// =====================================================================

/**
 * 整数钳制：非有限数（NaN/Infinity/非数字）返回默认值，否则取整并钳到 [min,max]。
 * @param {unknown} v 输入值
 * @param {number|undefined} def 非法时的默认值（**可为 undefined** —— 历史调用点
 *   确实传 undefined，此时非法输入返回 undefined 而非数字）
 * @param {number} min 下界
 * @param {number} max 上界
 * @returns {number|undefined} 钳制后的整数，或 undefined
 */
export function clampInt(v, def, min, max) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(Math.min(max, Math.max(min, n))) : def;
}

/**
 * 浮点数钳制：与 clampInt 的差别是**不取整**（时间阈值等需要小数精度）。
 * @param {unknown} v 输入值
 * @param {number|undefined} def 非法时的默认值（可为 undefined，同 clampInt）
 * @param {number} min 下界
 * @param {number} max 上界
 * @returns {number|undefined} 钳制后的数值，或 undefined
 */
export function clampNum(v, def, min, max) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
}

/**
 * 布尔归一：null/undefined 用默认值，其余走真值判定。
 * @param {unknown} v 输入值
 * @param {boolean} [def] null/undefined 时的默认值
 * @returns {boolean} 布尔值
 */
export function boolOf(v, def = false) {
  return v === undefined || v === null ? def : !!v;
}

/**
 * 字符串钳制：截断到 maxLen。
 *
 * ⚠ 边界语义（勿"顺手优化"）：
 *   · null/undefined → **undefined**（不是默认值）—— 表示「该键不写入」；
 *   · 空串 → **undefined**（空串在多数配置键上是"没配"，不是"配成空"）；
 *   · 短于 maxLen → 原样返回（不填充、不 trim）。
 * @param {unknown} v 输入值
 * @param {unknown} def 保留参数（历史签名）；当前实现不使用，恒按 undefined 处理
 * @param {number} maxLen 最大长度
 * @returns {string|undefined} 截断后的字符串，或 undefined
 */
export function clampStr(v, def, maxLen) {
  if (v === undefined || v === null) return undefined;
  const s = String(v);
  if (s === '') return undefined;
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

/**
 * 从配置对象取值并整数钳制。**未传（null/undefined）→ undefined**（不是默认值）。
 * @param {object} cfg 配置对象
 * @param {string} key 键名
 * @param {number|undefined} def 非法时的默认值（可为 undefined）
 * @param {number} min 下界
 * @param {number} max 上界
 * @returns {number|undefined} 钳制后的整数，或 undefined（未传）
 */
export function pickInt(cfg, key, def, min, max) {
  const v = cfg[key];
  return v === undefined || v === null ? undefined : clampInt(v, def, min, max);
}

/**
 * 从配置对象取值并布尔归一。**未传 → undefined**（与 pickInt 同构）。
 * @param {object} cfg 配置对象
 * @param {string} key 键名
 * @returns {boolean|undefined} 布尔值，或 undefined（未传）
 */
export function pickBool(cfg, key) {
  const v = cfg[key];
  return v === undefined || v === null ? undefined : boolOf(v);
}

/**
 * Cookie 映射消毒（storeCookies / triggerCookies 共用）。
 *
 * [todo#39 2026-09-11] 二阶跨角色触发：仅保留字符串键值对；
 * 过滤原型污染键（__proto__ / constructor / prototype）；上限 32 键防滥用。
 *
 * ⚠ 原型污染过滤是**安全边界**：`{"__proto__": {...}}` 若原样合并进配置对象，
 * 会污染 Object.prototype（影响整个进程），不是"数据不好看"的问题。
 *
 * @param {unknown} v 输入值
 * @returns {Record<string,string>|undefined} 消毒后的映射；无有效键时返回 undefined
 */
export function sanitizeCookieMap(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
  const out = /** @type {Record<string, string>} */ ({});
  let n = 0;
  for (const [k, val] of Object.entries(v)) {
    if (n >= 32) break;
    if (typeof k !== 'string' || typeof val !== 'string') continue;
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (!k.trim() || k.length > 256 || val.length > 4096) continue;
    out[k] = val;
    n++;
  }
  return n ? out : undefined;
}

/**
 * 参数表（bodyParams / cookieParams）的长度 + 数量限制。
 *
 * [安全审计 P1] 防超大 body 注入 / 超多参数 DoS
 * （对标 headerParams 黑名单过滤的安全级别）。
 *
 * ⚠ 注意：`count++` 在**每次迭代**执行（`continue` 分支不会走到），
 * 所以 maxKeys 限制的是「遍历过的条目数」而非「写入的条目数」——
 * 这是既有行为，勿"顺手改成只计写入数"（会放宽 DoS 上限）。
 *
 * @param {unknown} params 输入参数表
 * @param {number} [maxKeys] 最多遍历条目数
 * @param {number} [maxValLen] 单值最大长度
 * @param {number} [maxKeyLen] 键名最大长度
 * @returns {Record<string,string>} 消毒后的参数表（非对象输入返回 {}）
 */
export function clampParams(params, maxKeys = 50, maxValLen = 10000, maxKeyLen = 100) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return {};
  const out = /** @type {Record<string, string>} */ ({});
  let count = 0;
  for (const [k, v] of Object.entries(params)) {
    if (count >= maxKeys) break;
    const key = String(k).slice(0, maxKeyLen);
    const val = typeof v === 'string' ? v.slice(0, maxValLen) : String(v ?? '').slice(0, maxValLen);
    out[key] = val;
    count++;
  }
  return out;
}

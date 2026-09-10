// 拦截页响应策略（纯函数决策器）——把「识别结论」变成「下一步怎么发包」。
//
// 为什么需要它：识别结果此前只用于前端提示，不改变发包形态，导致识别出 WAF 与没识别出
// 的处理完全一样（继续裸打）。本模块给出**建议**（preferTamper / pause），由调用方执行；
// 它自己不发请求、不改配置、不 sleep——保持纯函数便于单测与在 scanRunner 之外先固化契约。
//
// 决策保守原则（与 blockSignatures 一致）：
//   · 'unknown' 一票否决：主动探测兜底拿不到厂商名时会被写成 vendor='unknown'（无签名证据），
//     本模块对它只返回 'none'，绝不递出 tamper 建议——防止下游拿 _default 链重跑全站未命中点。
//   · 只有「通用拦截页命中」才建议换形态；用户已显式配置 tamper 时绝不覆盖（尊重人工接管）。
//   · preferTamper 只是建议链（hint），不自动套用——真正套用仍由 autoRetry/WAF_HIGH_CONFIDENCE 门控。
//   · 429/503 是容量信号：优先级高于换形态（先降速，再谈绕过），否则 tamper 重跑会在目标
//     已过载时继续加压。退避时长只信 Retry-After，非法/缺失就不退避——宁可不等待，也不臆造
//     一个等待值把扫描挂住；上限 MAX_BACKOFF_MS 防被服务端超长 Retry-After 冻住整轮扫描。

import { recommend } from './wafRecommend.js';
import { RATE_LIMIT_STATUSES, GENERIC_BLOCK_VENDOR } from './blockSignatures.js';

// Retry-After 换算后的退避上限（30s）：超过部分截断，避免单次退避拖垮整轮扫描预算
export const MAX_BACKOFF_MS = 30_000;

// 不可信任的 vendor 标记：主动探测兜底拿不到厂商名时，调用侧会写成 'unknown'
// （scanRunner 的 `probeResult.vendor || 'unknown'`）。这类结论零签名证据，一旦递出 preferTamper，
// 下游就会拿 wafRecommend 的 `_default` 推荐链重跑全站未命中点（流量翻倍）。
// 故本模块把它一票否决：action 只能 'none'、tamperHint 必为空（优先级高于 pause / preferTamper）。
const UNTRUSTED_VENDORS = new Set(['unknown', 'unknown waf']);

// 大小写不敏感取响应头值（与 WafIdentifier 同款小工具，避免依赖实现细节）
function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return undefined;
  const target = String(key).toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

// 截断到 [0, MAX_BACKOFF_MS]
function clampBackoff(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return 0;
  return Math.min(MAX_BACKOFF_MS, Math.round(ms));
}

/**
 * 解析 Retry-After，支持两种合法格式（RFC 9110 §10.2.3）：
 *   1) delta-seconds：`120`（部分网关会给小数 `0.5`）
 *   2) HTTP-date：`Wed, 21 Oct 2026 07:28:00 GMT`
 * 非法值（垃圾串、无法解析的日期）一律返回 null —— 忽略而不是兜底一个默认等待时长，
 * 因为「猜测的退避」既可能拖慢扫描也可能完全无效，不如交给上层常规节流桶。
 * @param {string|number|null|undefined} raw Retry-After 原始值
 * @param {number} [now] 当前时间戳（可注入便于测试 HTTP-date 分支）
 * @returns {number|null} 毫秒；null 表示无有效退避信息
 */
export function parseRetryAfter(raw, now = Date.now()) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!s) return null;
  // 纯数字（含可选小数）按秒处理
  if (/^\d+(?:\.\d{1,3})?$/.test(s)) return clampBackoff(Number(s) * 1000);
  const ts = Date.parse(s);
  if (Number.isNaN(ts)) return null; // 非法日期 → 忽略
  // 已过期（服务端时钟偏差/日期已过）→ 0，语义是「不必等待，立即恢复」，不臆造正数
  return clampBackoff(ts - now);
}

// 用户是否已显式接管 tamper（enabled 或给定 plugins 非空）——与 WafIdentifier.shouldAutoRetry 同判据
function isUserTamperExplicit(config) {
  const tamper = (config && config.wafEvasion && config.wafEvasion.tamper) || {};
  return !!tamper.enabled || (Array.isArray(tamper.plugins) && tamper.plugins.length > 0);
}

// 归一化 vendor 输入：允许字符串（厂商名）或候选对象（{vendor, confidence}）
function vendorOf(v) {
  if (!v) return null;
  if (typeof v === 'string') return v;
  return typeof v.vendor === 'string' ? v.vendor : null;
}

/**
 * 是否为不可信任的 'unknown' 类 vendor。只看显式给出的厂商名：
 * namedVendor 缺失（仅通用拦截页命中、无厂商可命名）不算 unknown，不该被误否决。
 * @param {string|{vendor?:string}|null|undefined} v vendor 名或候选对象
 * @returns {boolean}
 */
export function isUntrustedVendor(v) {
  const s = vendorOf(v);
  return typeof s === 'string' && UNTRUSTED_VENDORS.has(s.trim().toLowerCase());
}

/**
 * 依据「拦截识别结论 + 响应状态/头」给出下一步发包策略（纯函数，无副作用）。
 *
 * 契约（返回值固定四字段，调用方可无条件消费）：
 *   { action: 'none' | 'preferTamper' | 'pause',
 *     tamperHint: string[],        // 建议的 tamper 链（有序）；无建议时为空数组
 *     backoffMs: number|null,      // 需要退避时的毫秒数（已截断到 30s）；否则 null
 *     reason: string }             // 决策依据（进日志/报告，便于复盘为什么改了形态）
 *
 * 规则优先级（unknown 否决 > pause > preferTamper > none）：
 *   0) vendor === 'unknown'（主动探测兜底，无签名证据）→ 不论还有其它什么信号，action 只能 'none'
 *      且 tamperHint 置空：不把发包形态变更（也不给 autoRetry 语义）交给一个「不知是谁」的结论。
 *      容量退避与厂商标识无关，调用方需要时用 parseRetryAfter 单独处理（本函数不代它下发）。
 *   1) status ∈ {429,503} 且 Retry-After 可解析 → pause（容量信号优先，避免在过载目标上加压）；
 *      此时若同时命中通用拦截页，仍把推荐链放进 tamperHint 作为退避后的建议，不丢信息。
 *   2) 命中 generic_block 且用户未显式配置 tamper → preferTamper + wafRecommend 推荐链。
 *   3) 其余 → none（不改形态、不额外等待）。
 *
 * @param {{genericBlock?:object|null, namedVendor?:string|{vendor:string}, status?:number, headers?:object, config?:object}} input
 * @returns {{action:'none'|'preferTamper'|'pause', tamperHint:string[], backoffMs:number|null, reason:string}}
 */
export function decideBlockPolicy(input = {}) {
  const { genericBlock, namedVendor, headers, config } = input;
  const status = Number(input.status ?? genericBlock?.status);
  const hit = !!genericBlock;
  const ids = Array.isArray(genericBlock?.matchedIds) ? genericBlock.matchedIds.join(', ') : (genericBlock?.id || 'generic_block');

  // 建议链：已命名厂商优先用厂商推荐（wafRecommend 有差异化映射），否则 generic_block 落到 _default 链
  const chainFor = (vendor) => {
    const list = recommend([{ vendor, confidence: genericBlock?.confidence ?? 0.55, evidence: ids }]);
    return list.length > 0 ? [...list[0].plugins] : [];
  };
  const named = vendorOf(namedVendor);
  const hint = hit ? chainFor(named || GENERIC_BLOCK_VENDOR) : [];
  const family = genericBlock?.family ? ` family=${genericBlock.family}` : '';

  // 0) 'unknown' 一票否决（先看已命名厂商候选，再看通用候选自带的 vendor 标记）：
  // 宁可不作为，也不把一个不存在的厂商结论变成全站 tamper 重跑。
  if (isUntrustedVendor(named) || isUntrustedVendor(genericBlock)) {
    // 把本可生效的退避时长写进 reason（仅审计），避免接线人误判为数据丢失
    const ignoredBackoff = RATE_LIMIT_STATUSES.has(status) ? parseRetryAfter(getHeader(headers, 'retry-after')) : null;
    return {
      action: 'none',
      tamperHint: [],
      backoffMs: null,
      reason: `vendor='unknown'（无签名证据的兜底结论）→ 否决任何发包形态变更${
        ignoredBackoff != null ? `；已忽略 Retry-After≈${ignoredBackoff}ms，容量退避请调用方用 parseRetryAfter 单独处理` : ''
      }`,
    };
  }

  // 1) 限流/过载 + 可解析的 Retry-After → 退避优先
  if (RATE_LIMIT_STATUSES.has(status)) {
    const backoffMs = parseRetryAfter(getHeader(headers, 'retry-after'));
    if (backoffMs != null) {
      return {
        action: 'pause',
        tamperHint: hit ? hint : [],
        backoffMs,
        reason: `status=${status} 为限流/过载信号且 Retry-After 有效，退避 ${backoffMs}ms${hit ? `（同时命中通用拦截页：${ids}${family}）` : '）'}`,
      };
    }
  }

  // 2) 通用拦截页命中 → 建议换形态；用户已显式配置 tamper 时不覆盖
  if (hit) {
    if (isUserTamperExplicit(config)) {
      return {
        action: 'none',
        tamperHint: [],
        backoffMs: null,
        reason: `命中通用拦截页（${ids}${family}）但用户已显式配置 tamper，不覆盖人工接管`,
      };
    }
    return {
      action: 'preferTamper',
      tamperHint: hint,
      backoffMs: null,
      reason: `命中通用拦截页（${ids}${family}，confidence=${genericBlock?.confidence ?? 0.55}）：建议按推荐链发包${named ? `（已识别厂商 ${named}）` : ''}`,
    };
  }

  // 3) 无证据 → 保持现状
  return {
    action: 'none',
    tamperHint: [],
    backoffMs: null,
    reason: '无拦截证据，保持当前发包形态',
  };
}

export default decideBlockPolicy;

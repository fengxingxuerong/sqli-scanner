// ============================================================================
// core/getHeader.js —— 响应头大小写不敏感取值（全仓唯一实现）
//
// 为什么单独成文件：WAF 判定（WafIdentifier / blockPolicy）与扫描有效性判定
// （scanValidityGuard）都依赖「同一响应头读取口径」，此前三处各有一份独立实现且
// 已经漂移 —— scanValidityGuard 版支持 AxiosHeaders 样对象（.get 方法）并做 String 化，
// blockPolicy 版处理了数组值取首元素，WafIdentifier 版两者皆无。
// header 读取是三处结论的共同前置：任一处裁剪规则漂移 ⇒ 同一响应在三处结论不一致，
// 且这种不一致不报错、只悄悄改判（docs/优化空间评估-2026-09-26.md §3）。
// 2026-09-29 收敛为本文件，三处全部改为导入本实现（语义 = 原 scanValidityGuard 强版）。
//
// 数组值口径刻意取 **String(v)（逗号拼接）** 而不是取首元素：
//   · 多值头最常见的 set-cookie 正是 WAF 指纹（F5 BIGIPServer 等）的匹配目标，
//     取首元素会漏掉「签名在第二条 cookie」的命中；
//   · 旧 scanValidityGuard / WafIdentifier 的实际生效行为就是 String(v) 拼接
//     （前者直接 String，后者返回原数组、由 matchOne 再 String），收敛后两处零漂移；
//   · blockPolicy 的 Retry-After 解析从不面对数组值，首元素 ⇒ 拼接对它无实际影响。
// ============================================================================

/**
 * 大小写不敏感取响应头（axios headers 可能是 AxiosHeaders / 普通对象 / Map 样对象）。
 * @param {object} headers
 * @param {string} key
 * @returns {string|undefined}
 */
export function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return undefined;
  const target = String(key).toLowerCase();
  if (typeof headers.get === 'function') {
    const v = headers.get(target);
    if (v != null) return String(v);
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === target) return v == null ? undefined : String(v);
  }
  return undefined;
}

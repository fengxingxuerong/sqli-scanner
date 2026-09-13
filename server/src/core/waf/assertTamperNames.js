// WAF → 推荐名合法性静态断言（WAF-v2 防呆）。
// 遍历 WAF_RECOMMEND_MAP 全部值，断言每个插件名都在 tamperRegistry 已注册清单中。
// 由 wafRecommend.js 在模块加载期调用（fail-fast），单测亦可显式调用固化契约。
import { tamperRegistry } from '../tamper/index.js';
import { WAF_RECOMMEND_MAP } from './wafRecommendMap.js';

/**
 * 校验 WAF_RECOMMEND_MAP 引用的所有 tamper 插件名均已注册。
 * @param {Set<string>|Array<string>} [registered] 已注册名集合/数组（默认从 tamperRegistry.list() 取）
 * @returns {true} 通过
 * @throws {Error} 一旦发现未注册名（含 vendor 与插件名，便于定位）
 */
export function assertRecommendNames(registered) {
  const names = registered
    ? new Set(Array.from(registered))
    : new Set(tamperRegistry.list().map((t) => t.name));
  const bad = [];
  for (const [vendor, plugins] of Object.entries(WAF_RECOMMEND_MAP)) {
    for (const p of plugins || []) {
      if (!names.has(p)) bad.push(`vendor="${vendor}" -> "${p}"`);
    }
  }
  if (bad.length) {
    throw new Error(`[WAF_RECOMMEND_MAP] 引用未注册 tamper 插件: ${bad.join('; ')}`);
  }
  return true;
}

export default assertRecommendNames;

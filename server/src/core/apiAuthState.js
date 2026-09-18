// ============================================================================
// core/apiAuthState.js —— 「本次进程是否启用了 API 鉴权」的共享状态
//
// 为什么单独一个模块：
//   index.js 需要把 resolveApiToken() 的结论告诉 sqlmapBridge（`--eval` 这类高危能力的
//   门控条件之一是「引擎必须已启用鉴权」）。若 sqlmapBridge 直接 import index.js，
//   会形成 index → sqlmapRoutes → sqlmapBridge → index 的循环依赖，启动期极易踩到
//   半初始化模块（拿到 undefined）。这里只存一个布尔值，零依赖、无循环风险。
//
// 语义：*鉴权是否已启用*，不是「token 值」。不要在别处用它做任何凭据判断。
// ============================================================================

let authEnabled = false;

/** @param {boolean} v 引擎是否已启用 API 鉴权（index.js 在解析 token 后调用一次） */
export function setAuthEnabled(v) {
  authEnabled = Boolean(v);
}

/** @returns {boolean} 当前进程是否启用了 API 鉴权 */
export function isAuthEnabled() {
  return authEnabled;
}

// 测试钩子：允许用例重置状态（生产代码不应调用）
export function _resetAuthStateForTest() {
  authEnabled = false;
}

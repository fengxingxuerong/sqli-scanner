// ============================================================================
// core/tamper/headerSink.js —— 请求头注入契约的**唯一真源**
//
// ⚠️ 为什么放在 tamper/ 而不是 tamper/plugins/ 下（同 quoteScan.js 的处置）：
//   plugins/ 里的每个文件都必须注册到 tamperRegistry ——
//   tamperPluginCount.guard.test.js 的「目录 ⇄ 注册表」双向对账会把
//   "存在但未注册"判为"能写不能用 = 能力缺失"。而本模块是**共享工具**，
//   不是可启用的插件，注册它反而会让注册表多出一个语义不明的条目。
//
// 为什么独立成模块（2026-10-05 实测，header 类插件在真实链路上静默失效）
// ----------------------------------------------------------------------------
// 四个写请求头的插件此前分成**两套不同的注入契约**：
//
//   varnish.js / xforwardedfor.js —— 完整实现（ctx.headers → 回退 target.headerParams）
//   agent.js / arges.js           —— 只读 ctx.headers，**无回退**
//
// 而引擎传给插件的 ctx 来自 obfuscateWithConfig → applyTampers → _runChain，
// 它的真实形态是检测器上下文 `{ httpClient, target, point, dbms, config }`，
// **根本没有 ctx.headers 这个顶层键**（实测 `'headers' in ctx === false`）。
//
// 引擎读请求头走 buildInjectionRequest，它展开的是 **target.headerParams**
// （实测：写进去的头确实出现在 req.headers 里）。
//
// 于是只读 ctx.headers 的两个插件在真实链路上把头全丢了 ——
// 实测走 obfuscateWithConfig：
//     插件 [agent]  → target.headerParams 写前 {} 写后 {}   ← UA 伪装静默失效
//     插件 [arges]  → target.headerParams 写前 {} 写后 {}   ← IP 伪造静默失效
//     插件 [varnish] / [xforwardedfor] → 正常写入
//
// 方向是**降低检出能力**：agent 伪装 User-Agent（扫描器最易被识别的特征），
// arges 伪造来源 IP。两者失效时不报错、不告警，插件看起来"已启用"。
//
// 这正是 core/http/ipBytes.js 注释里警告过的形态：
//   「同一判据多份实现，一份修了另一份没修」—— 本仓反复吃过这个亏。
// 故收敛为唯一真源；tests/tamperHeaderInjectionSingleSource.test.js 双向钉住
// （既要每个插件真的写入，也要没有任何插件再私藏副本）。
//
// 优先级说明：ctx.headers 优先于 target.headerParams。
//   · 两者都在时，ctx.headers 是调用方**本次调用**的临时接收器，
//     写它不会污染 target（target.headerParams 会随 target 跨请求复用）。
//   · 只有 target 可写时（引擎真实形态）才落到 target.headerParams。
// ============================================================================

/**
 * 取本次 tamper 调用可写的请求头容器。
 *
 * @param {object|null|undefined} ctx 检测上下文 { httpClient, target, point, dbms, config }
 * @returns {object|null} 可写的头容器；null 表示无处可写（插件应退化为恒等变换）
 */
export function headerSink(ctx) {
  if (!ctx || typeof ctx !== 'object') return null;

  // ① 调用方显式提供的临时容器 —— 优先，且不污染 target
  const h = ctx.headers;
  if (h && typeof h === 'object' && !Array.isArray(h)) return h;

  // ② 引擎真实形态：target.headerParams（buildInjectionRequest 会展开它）
  const t = ctx.target;
  if (t && typeof t === 'object') {
    if (!t.headerParams || typeof t.headerParams !== 'object' || Array.isArray(t.headerParams)) {
      t.headerParams = {};
    }
    return t.headerParams;
  }

  return null;
}

export default headerSink;
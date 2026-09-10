/**
 * secondOrderMethod.js —— 二阶请求的方法治理
 * [P0-FIX 2026-09-09]
 *
 * 为什么单独一个文件：二阶检测天然要「先写一次，再看回显」，是整台扫描器里唯一会
 * **主动改目标数据**的通路。原实现把用户填的 `secondMethod` 原样交给 HTTP 层（TRACE/CONNECT
 * 都能发出去），触发页又硬编码 GET（对 `/order/create?id=1` 这种 GET 写端点等于照打），
 * 于是「我们只做只读复核」这句话在代码层面并不成立。
 *
 * 语义：
 *   · 白名单外的方法（TRACE/OPTIONS 之外的任意串、CONNECT、含 CR/LF 的值）→ 回落 GET（绝不抛，
 *     否则一个拼错的方法名会把整轮二阶检测打成红字，现场反而更难归因）；
 *   · productionMode=true（默认）时非幂等方法必须 `secondOrder.allowWrites===true` 才放行，
 *     否则跳过该触发目标并在 report.summary.constraints 里留话；
 *   · 未显式配置方法时保持历史行为（GET），零回归。
 */

export const SECOND_ORDER_ALLOWED_METHODS = Object.freeze([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);
/** 幂等方法：不会改变目标状态，生产环境下无需额外确认 */
export const SECOND_ORDER_IDEMPOTENT_METHODS = Object.freeze(['GET', 'HEAD']);

/**
 * 归一并裁决本次二阶请求应使用的方法。
 * @param {string|null|undefined} raw 用户配置的方法（secondMethod / triggerMethod）
 * @param {{productionMode?:boolean, allowWrites?:boolean}} [policy]
 * @returns {{method:string, skipped:boolean, reason:string}} method 为最终应使用的方法；
 *          skipped=true 表示本次不应发出该请求（reason 说明原因）
 */
export function resolveSecondOrderMethod(raw, policy = {}) {
  const productionMode = policy.productionMode !== false;
  const allowWrites = policy.allowWrites === true;
  // 只取首行、去空白、大写：顺手掐掉 CRLF（方法名里带 \r\n 就是请求行注入）
  const rawStr = String(raw ?? '').split(/[\r\n]/)[0].trim().toUpperCase();
  if (!rawStr) return { method: 'GET', skipped: false, reason: '' };
  if (!SECOND_ORDER_ALLOWED_METHODS.includes(rawStr)) {
    return {
      method: 'GET',
      skipped: false,
      reason: `不支持的二阶请求方法「${rawStr}」已回落 GET（白名单：${SECOND_ORDER_ALLOWED_METHODS.join('/')}）`,
    };
  }
  if (productionMode && !allowWrites && !SECOND_ORDER_IDEMPOTENT_METHODS.includes(rawStr)) {
    return {
      method: rawStr,
      skipped: true,
      reason:
        `productionMode=true 时跳过非幂等二阶请求（${rawStr}）：写请求会改目标数据，` +
        '需显式设 secondOrder.allowWrites=true',
    };
  }
  return { method: rawStr, skipped: false, reason: '' };
}

export default resolveSecondOrderMethod;

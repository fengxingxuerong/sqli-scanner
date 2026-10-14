// 相等 → LIKE 替换：将 = 替换为 LIKE，绕过 = 过滤规则（对标 sqlmap noequals.py）
// 引号内不替换（字面量里的 = 是数据不是比较符）；行注释区原样透传。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号/注释状态机。
import { walkLiterals } from '../literalWalk.js';

export const noequals = {
  name: 'noequals',
  description: '将 = 替换为 LIKE，绕过 WAF 对等号的过滤规则（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/=/g, 'LIKE'),
    });
  },
};
export default noequals;

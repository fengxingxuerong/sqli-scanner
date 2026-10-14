// 反斜杠 -> 正斜杠，绕过路径过滤和 WAF 规则（对标 sqlmap backslash2forward.py）
// 引号内原样透传：字符串字面量里的 \ 是转义前缀，动它会破坏 payload 语义。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const backslash2forward = {
  name: 'backslash2forward',
  description: '将反斜杠替换为正斜杠，绕过路径过滤（引号状态机保护字符串字面量）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/\\/g, '/'),
    });
  },
};
export default backslash2forward;

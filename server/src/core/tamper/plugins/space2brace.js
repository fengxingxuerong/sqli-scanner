// 空格 → 花括号：将空格替换为花括号 {}（对标 sqlmap space2brace.py）
import { walkLiterals } from '../literalWalk.js';

export const space2brace = {
  name: 'space2brace',
  description: '将空格替换为花括号 {}，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '{}'),
    });
  },
};
export default space2brace;

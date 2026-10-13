// 空格 → 方括号：将空格替换为方括号 []（对标 sqlmap space2bracket.py）
import { walkLiterals } from '../literalWalk.js';

export const space2bracket = {
  name: 'space2bracket',
  description: '将空格替换为方括号 []，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '[]'),
    });
  },
};
export default space2bracket;

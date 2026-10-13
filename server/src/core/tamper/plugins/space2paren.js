// 空格 → 括号：将空格替换为括号 ()（对标 sqlmap space2paren.py）
import { walkLiterals } from '../literalWalk.js';

export const space2paren = {
  name: 'space2paren',
  description: '将空格替换为括号 ()，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '()'),
    });
  },
};
export default space2paren;

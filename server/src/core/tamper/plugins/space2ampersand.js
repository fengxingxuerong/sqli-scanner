// 空格 → & 符号：将空格替换为 & 符号（对标 sqlmap space2ampersand.py）
import { walkLiterals } from '../literalWalk.js';

export const space2ampersand = {
  name: 'space2ampersand',
  description: '将空格替换为 & 符号，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '&'),
    });
  },
};
export default space2ampersand;

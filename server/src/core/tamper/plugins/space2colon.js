// 空格 → 冒号：将空格替换为冒号 :（对标 sqlmap space2colon.py）
import { walkLiterals } from '../literalWalk.js';

export const space2colon = {
  name: 'space2colon',
  description: '将空格替换为冒号 :，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, ':'),
    });
  },
};
export default space2colon;

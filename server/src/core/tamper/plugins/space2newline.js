// 空格 → 换行符：将空格替换为换行符（对标 sqlmap space2newline.py）
import { walkLiterals } from '../literalWalk.js';

export const space2newline = {
  name: 'space2newline',
  description: '将空格替换为换行符，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '\n'),
    });
  },
};
export default space2newline;

// 空格 → 回车符：将空格替换为回车符（对标 sqlmap space2carriage.py）
import { walkLiterals } from '../literalWalk.js';

export const space2carriage = {
  name: 'space2carriage',
  description: '将空格替换为回车符，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '\r'),
    });
  },
};
export default space2carriage;

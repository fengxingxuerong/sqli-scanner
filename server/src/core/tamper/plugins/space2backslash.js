// 空格 → 反斜杠：将空格替换为反斜杠（对标 sqlmap space2backslash.py）
import { walkLiterals } from '../literalWalk.js';

export const space2backslash = {
  name: 'space2backslash',
  description: '将空格替换为反斜杠 \\，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '\\\\'),
    });
  },
};
export default space2backslash;

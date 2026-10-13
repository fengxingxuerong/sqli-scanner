// 空格 → 宽字符空格：将空格替换为全角空格（对标 sqlmap space2widechar.py）
import { walkLiterals } from '../literalWalk.js';

export const space2widechar = {
  name: 'space2widechar',
  description: '将空格替换为全角空格 \\u3000，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '\u3000'),
    });
  },
};
export default space2widechar;

// 空格 → Unicode 空格：将空格替换为 Unicode 不间断空格（对标 sqlmap space2unicode.py）
import { walkLiterals } from '../literalWalk.js';

export const space2unicode = {
  name: 'space2unicode',
  description: '将空格替换为 Unicode 不间断空格 \\u00A0，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '\u00A0'),
    });
  },
};
export default space2unicode;

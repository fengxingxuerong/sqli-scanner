// 空格 → 等号：将空格替换为等号 =（对标 sqlmap space2equal.py）
import { walkLiterals } from '../literalWalk.js';

export const space2equal = {
  name: 'space2equal',
  description: '将空格替换为等号 =，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '='),
    });
  },
};
export default space2equal;

// 空格 → 大于号：将空格替换为大于号 >（对标 sqlmap space2gt.py）
import { walkLiterals } from '../literalWalk.js';

export const space2gt = {
  name: 'space2gt',
  description: '将空格替换为大于号 >，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '>'),
    });
  },
};
export default space2gt;

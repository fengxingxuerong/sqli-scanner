// 空格 → 小于号：将空格替换为小于号 <（对标 sqlmap space2lt.py）
import { walkLiterals } from '../literalWalk.js';

export const space2lt = {
  name: 'space2lt',
  description: '将空格替换为小于号 <，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '<'),
    });
  },
};
export default space2lt;

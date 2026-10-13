// 空格 → 百分号：将空格替换为 % 符号（对标 sqlmap space2percent.py）
import { walkLiterals } from '../literalWalk.js';

export const space2percent = {
  name: 'space2percent',
  description: '将空格替换为百分号 %，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '%'),
    });
  },
};
export default space2percent;

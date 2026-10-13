// 空格 → 点号：将空格替换为点号 .（对标 sqlmap space2dot.py）
import { walkLiterals } from '../literalWalk.js';

export const space2dot = {
  name: 'space2dot',
  description: '将空格替换为点号 .，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '.'),
    });
  },
};
export default space2dot;

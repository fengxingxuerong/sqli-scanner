// 空格 → 逗号：将空格替换为逗号 ,（对标 sqlmap space2comma.py）
import { walkLiterals } from '../literalWalk.js';

export const space2comma = {
  name: 'space2comma',
  description: '将空格替换为逗号 ,，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, ','),
    });
  },
};
export default space2comma;

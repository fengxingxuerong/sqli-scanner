// 空格 → 斜杠：将空格替换为斜杠 /（对标 sqlmap space2slash.py）
import { walkLiterals } from '../literalWalk.js';

export const space2slash = {
  name: 'space2slash',
  description: '将空格替换为斜杠 /，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '/'),
    });
  },
};
export default space2slash;

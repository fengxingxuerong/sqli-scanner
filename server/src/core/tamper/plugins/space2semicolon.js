// 空格 → 分号：将空格替换为分号 ;（对标 sqlmap space2semicolon.py）
import { walkLiterals } from '../literalWalk.js';

export const space2semicolon = {
  name: 'space2semicolon',
  description: '将空格替换为分号 ;，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, ';'),
    });
  },
};
export default space2semicolon;

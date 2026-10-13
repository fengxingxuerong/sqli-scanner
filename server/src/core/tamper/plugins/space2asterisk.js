// 空格 → 星号：将空格替换为星号 *（对标 sqlmap space2asterisk.py）
import { walkLiterals } from '../literalWalk.js';

export const space2asterisk = {
  name: 'space2asterisk',
  description: '将空格替换为星号 *，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '*'),
    });
  },
};
export default space2asterisk;

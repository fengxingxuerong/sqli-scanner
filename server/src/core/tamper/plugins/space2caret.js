// 空格 → 脱字符：将空格替换为 ^ 符号（对标 sqlmap space2caret.py）
import { walkLiterals } from '../literalWalk.js';

export const space2caret = {
  name: 'space2caret',
  description: '将空格替换为脱字符 ^，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '^'),
    });
  },
};
export default space2caret;

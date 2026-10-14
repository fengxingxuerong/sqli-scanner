// 反转字符串：将字符串字面量反转后通过 REVERSE() 还原（对标 sqlmap reversestring.py）
// 例如：'admin' → REVERSE('nimda')。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const reversestring = {
  name: 'reversestring',
  description: '将字符串字面量反转后用 REVERSE() 还原，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `REVERSE(${quote}${body.split('').reverse().join('')}${quote})`,
    });
  },
};
export default reversestring;

// 字符 → ASCII 码编码：将字符串字面量中的字符编码为 ASCII 十进制（对标 sqlmap char2ascii.py）
// 适用于 WAF 对字符串内容的检测绕过。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const char2ascii = {
  name: 'char2ascii',
  description: '将字符串字面量编码为 ASCII 十进制数字序列，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `${quote}${body.split('').map((c) => c.charCodeAt(0).toString()).join('')}${quote}`,
    });
  },
};
export default char2ascii;

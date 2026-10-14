// 字符 → 十六进制转义：将字符串字面量内的字符编码为 \\xHH 转义序列（对标 sqlmap char2hex.py）
// 输出引号跟随原字面量（仅编码 body 内容）。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const char2hex = {
  name: 'char2hex',
  description: '将字符串字面量内的字符编码为 \\xHH 十六进制转义序列，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `${quote}${body.split('').map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')}${quote}`,
    });
  },
};
export default char2hex;

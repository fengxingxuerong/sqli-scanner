// 二进制 → ASCII：将字符串字面量编码为二进制位串（对标 sqlmap bin2ascii.py）
// 例如：'a' → 01100001。输出引号跟随原字面量（仅编码 body 内容）。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const bin2ascii = {
  name: 'bin2ascii',
  description: '将字符串字面量编码为二进制位串，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `${quote}${body.split('').map((c) => c.charCodeAt(0).toString(2).padStart(8, '0')).join('')}${quote}`,
    });
  },
};
export default bin2ascii;

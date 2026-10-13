// 字符串 → 十进制：将字符串字面量编码为十进制 CHAR() 序列（对标 sqlmap string2decimal.py）
import { walkLiterals } from '../literalWalk.js';

function string2decimalEncode(str) {
  return str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',');
}

export const string2decimal = {
  name: 'string2decimal',
  description: '将字符串字面量编码为十进制 CHAR() 序列，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(${string2decimalEncode(body)})`,
    });
  },
};
export default string2decimal;

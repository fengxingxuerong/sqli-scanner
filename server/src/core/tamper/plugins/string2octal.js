// 字符串 → 八进制：将字符串字面量编码为八进制表示（对标 sqlmap string2octal.py）
import { walkLiterals } from '../literalWalk.js';

function string2octalEncode(str) {
  return str.split('').map(c => `CHAR(0${c.charCodeAt(0).toString(8)})`).join(',');
}

export const string2octal = {
  name: 'string2octal',
  description: '将字符串字面量编码为八进制表示，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(${string2octalEncode(body)})`,
    });
  },
};
export default string2octal;

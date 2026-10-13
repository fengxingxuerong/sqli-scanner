// 八进制编码：将字符串字面量中的字符编码为八进制转义序列
// 对标 sqlmap octalencode.py
import { walkLiterals } from '../literalWalk.js';

function octalEncode(str) {
  return str.split('').map(c => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`).join('');
}

export const octalencode = {
  name: 'octalencode',
  description: '将字符串字面量编码为八进制转义序列，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `${quote}${octalEncode(body)}${quote}`,
    });
  },
};
export default octalencode;

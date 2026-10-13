// 双重 URL 编码：将字符串字面量中的字符进行双重 URL 编码（对标 sqlmap doubleencode.py）
import { walkLiterals } from '../literalWalk.js';

function doubleEncode(str) {
  return str.split('').map(c => `%25${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
}

export const doubleencode = {
  name: 'doubleencode',
  description: '双重 URL 编码字符串字面量，绕过 WAF 对 URL 编码的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `${quote}${doubleEncode(body)}${quote}`,
    });
  },
};
export default doubleencode;

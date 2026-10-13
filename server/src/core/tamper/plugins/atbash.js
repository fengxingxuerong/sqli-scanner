// Atbash 密码编码：将字符串字面量中的字母用 Atbash 密码编码（对标 sqlmap atbash.py）
// Atbash：A↔Z, B↔Y, C↔X, ... 通过 CHAR() 函数解码还原
import { walkLiterals } from '../literalWalk.js';

function atbashEncode(str) {
  return str.split('').map(c => {
    if (/[a-zA-Z]/.test(c)) {
      const code = c.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      return String.fromCharCode(base + (25 - (code - base)));
    }
    return c;
  }).join('');
}

export const atbash = {
  name: 'atbash',
  description: 'Atbash 密码编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `CONCAT(CHAR(90),${quote}${atbashEncode(body)}${quote})`,
    });
  },
};
export default atbash;

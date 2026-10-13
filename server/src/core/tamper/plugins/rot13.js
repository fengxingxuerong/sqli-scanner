// ROT13 编码：将字符串字面量中的字母用 ROT13 编码（对标 sqlmap rot13.py）
// 通过 CHAR() 函数解码还原
import { walkLiterals } from '../literalWalk.js';

function rot13Encode(str) {
  return str.split('').map(c => {
    if (/[a-zA-Z]/.test(c)) {
      const code = c.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      return String.fromCharCode(base + ((code - base + 13) % 26));
    }
    return c;
  }).join('');
}

export const rot13 = {
  name: 'rot13',
  description: 'ROT13 编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(CHAR(61),'${rot13Encode(body)}')`,
    });
  },
};
export default rot13;

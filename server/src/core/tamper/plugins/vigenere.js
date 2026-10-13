// Vigenere 密码编码：将字符串字面量中的字母用 Vigenere 密码编码（对标 sqlmap vigenere.py）
// 使用密钥 'sqlmap' 进行 Vigenere 编码，通过 CHAR() 函数解码还原
import { walkLiterals } from '../literalWalk.js';

const KEY = 'sqlmap';

function vigenereEncode(str) {
  let kidx = 0;
  return str.split('').map(c => {
    if (/[a-zA-Z]/.test(c)) {
      const code = c.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      const shift = KEY[kidx++ % KEY.length].toLowerCase().charCodeAt(0) - 97;
      return String.fromCharCode(base + ((code - base + shift) % 26));
    }
    return c;
  }).join('');
}

export const vigenere = {
  name: 'vigenere',
  description: 'Vigenere 密码编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(CHAR(115),'${vigenereEncode(body)}')`,
    });
  },
};
export default vigenere;

// Caesar 密码编码：将字符串字面量中的字母用 Caesar 移位编码（对标 sqlmap caesar.py）
// 移位量在 1-25 之间随机，通过 CHAR() 函数解码还原
import { walkLiterals } from '../literalWalk.js';

export const caesar = {
  name: 'caesar',
  description: 'Caesar 移位编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const shift = Math.floor(Math.random() * 24) + 1;
    const encode = (str) => str.split('').map(c => {
      if (/[a-zA-Z]/.test(c)) {
        const code = c.charCodeAt(0);
        const base = code >= 97 ? 97 : 65;
        return String.fromCharCode(base + ((code - base + shift) % 26));
      }
      return c;
    }).join('');
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `CONCAT(CHAR(${shift + 48}),${quote}${encode(body)}${quote})`,
    });
  },
};
export default caesar;

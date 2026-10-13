// 随机 ASCII 编码：将随机字符用 ASCII 编码（对标 sqlmap randomascii.py）
// 对 payload 中的一些字符随机选择用 CHAR() 编码
import { walkLiterals } from '../literalWalk.js';

function randomAsciiEncode(text) {
  return text.split('').map(ch => {
    if (/[a-zA-Z]/.test(ch) && Math.random() > 0.7) {
      return `CHAR(${ch.charCodeAt(0)})`;
    }
    return ch;
  }).join('');
}

export const randomascii = {
  name: 'randomascii',
  description: '随机选择字符用 CHAR() 编码，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => randomAsciiEncode(t),
    });
  },
};
export default randomascii;

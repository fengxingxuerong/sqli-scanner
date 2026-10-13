// XOR 编码：对字符串字面量中的字符进行 XOR 编码（对标 sqlmap xor.py）
// 使用固定密钥 0x1F，通过 CHAR() 函数解码还原
import { walkLiterals } from '../literalWalk.js';

const XOR_KEY = 0x1F;

function xorEncode(str) {
  const encoded = str.split('').map(c => (c.charCodeAt(0) ^ XOR_KEY).toString(16).padStart(2, '0')).join('');
  let out = `CHAR(${XOR_KEY})`;
  for (let k = 0; k < encoded.length; k += 2) {
    out += `+CHAR(0x${encoded[k]}${encoded[k + 1]})`;
  }
  return out;
}

export const xor = {
  name: 'xor',
  description: 'XOR 编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => xorEncode(body),
    });
  },
};
export default xor;

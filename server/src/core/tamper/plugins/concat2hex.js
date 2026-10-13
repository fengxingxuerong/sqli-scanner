// CONCAT → 十六进制编码：将字符串字面量用十六进制 + CONCAT 编码（对标 sqlmap concat2hex.py）
// 将字符串拆分为 CHAR(hex) 再 CONCAT 拼接
import { walkLiterals } from '../literalWalk.js';

function concat2hexEncode(str) {
  return str.split('').map(c => `0x${c.charCodeAt(0).toString(16)}`).join(',');
}

export const concat2hex = {
  name: 'concat2hex',
  description: '将字符串字面量编码为 CONCAT(CHAR(hex),...) 调用，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(${concat2hexEncode(body)})`,
    });
  },
};
export default concat2hex;

// 字符串 → 十六进制：将字符串字面量编码为十六进制 0xHEX 表示（对标 sqlmap str2hex.py）
// 例如：'admin' → 0x61646d696e
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const str2hex = {
  name: 'str2hex',
  description: '将字符串字面量编码为十六进制 0xHEX 表示，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `0x${Buffer.from(body).toString('hex')}`,
    });
  },
};
export default str2hex;

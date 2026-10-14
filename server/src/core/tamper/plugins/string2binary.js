// 字符串 → 二进制：将字符串字面量编码为二进制 0b 表示（对标 sqlmap string2binary.py）
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const string2binary = {
  name: 'string2binary',
  description: '将字符串字面量编码为二进制 0b 表示，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) =>
        `0b${body.split('').map((c) => c.charCodeAt(0).toString(2).padStart(8, '0')).join('')}`,
    });
  },
};
export default string2binary;

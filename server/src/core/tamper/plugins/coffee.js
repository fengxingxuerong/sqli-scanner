// CoffeeScript 编码：将字符串字面量用 CoffeeScript 风格的编码（对标 sqlmap coffee.py）
// 适用于使用 CoffeeScript 的 Node.js 后端。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const coffee = {
  name: 'coffee',
  description: 'CoffeeScript 编码字符串字面量，绕过 CoffeeScript 后端 WAF',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `${quote}${body.split('').map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')}${quote}`,
    });
  },
};
export default coffee;

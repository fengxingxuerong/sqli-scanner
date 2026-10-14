// CSS 编码：将字符串字面量用 CSS 反斜杠编码绕过（对标 sqlmap css.py）
// 适用于 ASP.NET 等使用 CSS 解析器的 WAF。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const css = {
  name: 'css',
  description: '将字符串字面量用 CSS 反斜杠十六进制编码，绕过 ASP.NET WAF',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `${quote}${body.split('').map((c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')} `).join('')}${quote}`,
    });
  },
};
export default css;

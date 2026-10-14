// 字符串 → LPAD 包装：将字符串字面量包装为 LPAD(char,length,string) 调用
// 对标 sqlmap lpad.py，绕过 WAF 字符串检测。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const lpad = {
  name: 'lpad',
  description: '将字符串字面量包装为 LPAD() 调用，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) =>
        `LPAD(${quote}${body}${quote},${body.length + 1},${quote}${body.slice(0, 1) || 'x'}${quote})`,
    });
  },
};
export default lpad;

// 十进制 -> CHAR() 编码：将字符串字面量中的每个字符转换为 CHAR(decimal) 调用
// 对标 sqlmap decimal2char.py，绕过 WAF 字符串检测
import { walkLiterals } from '../literalWalk.js';

function decimal2charEncode(str) {
  return str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',');
}

export const decimal2char = {
  name: 'decimal2char',
  description: '将字符串字面量编码为 CHAR(十进制) 序列，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `CONCAT(${decimal2charEncode(body)})`,
    });
  },
};
export default decimal2char;

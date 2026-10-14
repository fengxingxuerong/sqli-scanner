// JSON 转义：对字符串字面量内的 JSON 特殊字符做转义处理（对标 sqlmap jsonescape.py）
// 适用于 JSON API 场景。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

const JSON_SPECIAL = /[\\"\b\f\n\r\t]/g;

export const jsonescape = {
  name: 'jsonescape',
  description: '对字符串字面量中的 JSON 特殊字符做转义，绕过 JSON API WAF',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `${quote}${body.replace(JSON_SPECIAL, (c) => '\\' + c)}${quote}`,
    });
  },
};
export default jsonescape;

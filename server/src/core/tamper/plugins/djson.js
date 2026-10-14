// 双重 JSON 编码：将字符串字面量进行 JSON 双重编码绕过 WAF（对标 sqlmap djson.py）
// 适用于 JSON API 后端。输出引号跟随原字面量。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const djson = {
  name: 'djson',
  description: 'JSON 双重编码字符串字面量，绕过 JSON API WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => {
        const once = JSON.stringify(body);
        const twice = JSON.stringify(once);
        return `${quote}${twice.slice(1, -1)}${quote}`;
      },
    });
  },
};
export default djson;

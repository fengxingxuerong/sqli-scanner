// JSON 编码：将字符串字面量编码为 JSON 格式（对标 sqlmap json.py）
// 适用于 JSON API 后端，对 WAF 的字符串检测绕过效果好
import { walkLiterals } from '../literalWalk.js';

export const json = {
  name: 'json',
  description: '将字符串字面量 JSON 编码，绕过 JSON API WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body, quote) => `${quote}${JSON.stringify(body).slice(1, -1)}${quote}`,
    });
  },
};
export default json;

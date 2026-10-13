// Base64 编码（DEC2B64 变体）：将字符串字面量编码为 base64 后嵌入 TO_BASE64 调用
// 对标 sqlmap dbase64encode.py，与 base64encode（整体 base64）不同，仅编码字符串字面量
import { walkLiterals } from '../literalWalk.js';

export const dbase64encode = {
  name: 'dbase64encode',
  description: '将字符串字面量用 TO_BASE64() 包装，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `TO_BASE64('${Buffer.from(body).toString('base64')}')`,
    });
  },
};
export default dbase64encode;

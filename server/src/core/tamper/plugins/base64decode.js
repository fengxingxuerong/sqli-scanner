// Base64 解码：将字符串字面量用 base64 编码后通过 FROM_BASE64 解码还原
// 对标 sqlmap base64decode.py，与 base64encode（整体编码）不同，仅操作字符串字面量
import { walkLiterals } from '../literalWalk.js';

export const base64decode = {
  name: 'base64decode',
  description: '将字符串字面量 base64 编码后用 FROM_BASE64() 解码，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) => `FROM_BASE64('${Buffer.from(body).toString('base64')}')`,
    });
  },
};
export default base64decode;

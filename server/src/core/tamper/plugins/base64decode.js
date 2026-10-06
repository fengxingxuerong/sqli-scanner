// Base64 解码：将字符串字面量用 base64 编码后通过 FROM_BASE64 解码还原
// 对标 sqlmap base64decode.py，与 base64encode（整体编码）不同，仅操作字符串字面量
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const base64decode = {
  name: 'base64decode',
  description: '将字符串字面量 base64 编码后用 FROM_BASE64() 解码，绕过 WAF 字符串检测',
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
      const ch = src[i];
      if (inSingle) {
        if (ch === "'" && !isQuoteEscaped(src, i)) { inSingle = false; out += ch; }
        else out += ch;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && !isQuoteEscaped(src, i)) { inDouble = false; out += ch; }
        else out += ch;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, "'"); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `FROM_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `FROM_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default base64decode;

// 字符串 → 十六进制：将字符串字面量编码为十六进制 0xHEX 表示（对标 sqlmap str2hex.py）
// 例如：'admin' → 0x61646d696e
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const str2hex = {
  name: 'str2hex',
  description: '将字符串字面量编码为十六进制 0xHEX 表示，绕过 WAF 字符串检测',
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
        out += `0x${Buffer.from(str).toString('hex')}`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `0x${Buffer.from(str).toString('hex')}`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default str2hex;

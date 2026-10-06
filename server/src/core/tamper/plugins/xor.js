// XOR 编码：对字符串字面量中的字符进行 XOR 编码（对标 sqlmap xor.py）
// 使用固定密钥 0x1F，通过 CHAR() 函数解码还原
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const xor = {
  name: 'xor',
  description: 'XOR 编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const key = 0x1F;
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
        const encoded = str.split('').map(c => (c.charCodeAt(0) ^ key).toString(16).padStart(2, '0')).join('');
        out += `CHAR(${key})`;
        for (let k = 0; k < encoded.length; k += 2) {
          out += `+CHAR(0x${encoded[k]}${encoded[k + 1]})`;
        }
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = str.split('').map(c => (c.charCodeAt(0) ^ key).toString(16).padStart(2, '0')).join('');
        out += `CHAR(${key})`;
        for (let k = 0; k < encoded.length; k += 2) {
          out += `+CHAR(0x${encoded[k]}${encoded[k + 1]})`;
        }
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default xor;

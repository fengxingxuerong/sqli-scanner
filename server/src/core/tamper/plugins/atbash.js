// Atbash 密码编码：将字符串字面量中的字母用 Atbash 密码编码（对标 sqlmap atbash.py）
// Atbash：A↔Z, B↔Y, C↔X, ... 通过 CHAR() 函数解码还原
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const atbash = {
  name: 'atbash',
  description: 'Atbash 密码编码字符串字面量，绕过 WAF 字符串检测',
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
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(base + (25 - (code - base)));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(90),'${encoded}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(base + (25 - (code - base)));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(90),"${encoded}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default atbash;

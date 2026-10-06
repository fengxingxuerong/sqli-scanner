// Caesar 密码编码：将字符串字面量中的字母用 Caesar 移位编码（对标 sqlmap caesar.py）
// 移位量在 1-25 之间随机，通过 CHAR() 函数解码还原
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const caesar = {
  name: 'caesar',
  description: 'Caesar 移位编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const shift = Math.floor(Math.random() * 24) + 1;
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
            return String.fromCharCode(base + ((code - base + shift) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(${shift + 48}),'${encoded}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(base + ((code - base + shift) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(${shift + 48}),"${encoded}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default caesar;

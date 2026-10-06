// Vigenere 密码编码：将字符串字面量中的字母用 Vigenere 密码编码（对标 sqlmap vigenere.py）
// 使用密钥 'sqlmap' 进行 Vigenere 编码，通过 CHAR() 函数解码还原
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const vigenere = {
  name: 'vigenere',
  description: 'Vigenere 密码编码字符串字面量，绕过 WAF 字符串检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const key = 'sqlmap';
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
        let kidx = 0;
        { const lit = readSqlLiteral(src, i, "'"); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            const shift = key[kidx++ % key.length].toLowerCase().charCodeAt(0) - 97;
            return String.fromCharCode(base + ((code - base + shift) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(115),'${encoded}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        let kidx = 0;
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            const shift = key[kidx++ % key.length].toLowerCase().charCodeAt(0) - 97;
            return String.fromCharCode(base + ((code - base + shift) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(115),'${encoded}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default vigenere;

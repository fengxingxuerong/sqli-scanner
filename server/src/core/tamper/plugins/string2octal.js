// 字符串 → 八进制：将字符串字面量编码为八进制表示（对标 sqlmap string2octal.py）
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const string2octal = {
  name: 'string2octal',
  description: '将字符串字面量编码为八进制表示，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
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
        inSingle = true; let str = '';
        { const lit = readSqlLiteral(src, i, "'"); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `CONCAT(${str.split('').map(c => `CHAR(0${c.charCodeAt(0).toString(8)})`).join(',')})`;
      } else if (ch === '"') {
        inDouble = true; let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `CONCAT(${str.split('').map(c => `CHAR(0${c.charCodeAt(0).toString(8)})`).join(',')})`;
      } else out += ch;
    }
    return out;
  },
};
export default string2octal;

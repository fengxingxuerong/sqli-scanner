// 字符串 → 十进制：将字符串字面量编码为十进制 CHAR() 序列（对标 sqlmap string2decimal.py）
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const string2decimal = {
  name: 'string2decimal',
  description: '将字符串字面量编码为十进制 CHAR() 序列，绕过 WAF 字符串检测',
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
        out += `CONCAT(${str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',')})`;
      } else if (ch === '"') {
        inDouble = true; let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `CONCAT(${str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',')})`;
      } else out += ch;
    }
    return out;
  },
};
export default string2decimal;

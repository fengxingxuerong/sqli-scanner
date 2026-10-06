// 反转字符串：将字符串字面量反转后通过 REVERSE() 还原（对标 sqlmap reversestring.py）
// 例如：'admin' → REVERSE('nimda')
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const reversestring = {
  name: 'reversestring',
  description: '将字符串字面量反转后用 REVERSE() 还原，绕过 WAF 字符串检测',
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
        out += `REVERSE('${str.split('').reverse().join('')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `REVERSE("${str.split('').reverse().join('')}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default reversestring;

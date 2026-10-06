// CONCAT → 十六进制编码：将字符串字面量用十六进制 + CONCAT 编码（对标 sqlmap concat2hex.py）
// 将字符串拆分为 CHAR(hex) 再 CONCAT 拼接
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const concat2hex = {
  name: 'concat2hex',
  description: '将字符串字面量编码为 CONCAT(CHAR(hex),...) 调用，绕过 WAF 字符串检测',
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
        const hex = str.split('').map(c => `0x${c.charCodeAt(0).toString(16)}`).join(',');
        out += `CONCAT(${hex})`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const hex = str.split('').map(c => `0x${c.charCodeAt(0).toString(16)}`).join(',');
        out += `CONCAT(${hex})`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default concat2hex;

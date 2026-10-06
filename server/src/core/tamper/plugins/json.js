// JSON 编码：将字符串字面量编码为 JSON 格式（对标 sqlmap json.py）
// 适用于 JSON API 后端，对 WAF 的字符串检测绕过效果好
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const json = {
  name: 'json',
  description: '将字符串字面量 JSON 编码，绕过 JSON API WAF 检测',
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
      const ch = src[i];      if (inSingle) {
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
        const encoded = JSON.stringify(str);
        out += `'${encoded.slice(1, -1)}'`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        const encoded = JSON.stringify(str);
        out += `"${encoded.slice(1, -1)}"`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default json;

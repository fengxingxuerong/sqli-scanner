// Base64 编码（DEC2B64 变体）：将字符串字面量编码为 base64 后嵌入 TO_BASE64 调用
// 对标 sqlmap dbase64encode.py，与 base64encode（整体 base64）不同，仅编码字符串字面量
import { readSqlLiteral, isQuoteEscaped } from '../quoteScan.js';

export const dbase64encode = {
  name: 'dbase64encode',
  description: '将字符串字面量用 TO_BASE64() 包装，绕过 WAF 字符串检测',
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
        // 收集单引号字符串内容
        let str = '';
        { const lit = readSqlLiteral(src, i, "'"); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `TO_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        { const lit = readSqlLiteral(src, i, '"'); if (!lit.closed) { out += src.slice(i); return out; } i = lit.end; str = lit.body; }
        out += `TO_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default dbase64encode;

// 随机 ASCII 编码：将随机字符用 ASCII 编码（对标 sqlmap randomascii.py）
// 对 payload 中的一些字符随机选择用 CHAR() 编码
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const randomascii = {
  name: 'randomascii',
  description: '随机选择字符用 CHAR() 编码，绕过 WAF 关键字检测',
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
      const ch = src[i]
      if (inSingle) { out += ch; if (ch === "'" && !isQuoteEscaped(src, i)) inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && !isQuoteEscaped(src, i)) inDouble = false; continue; }
      if (ch === "'") {
        // [quoteScan] 未闭合字面量：原样透传剩余。原实现把尾部当普通字符逐个变换，
        // 对字面量编码型插件等于把 payload 尾部整个吃掉（SLEEP 关键字消失、
        // 注入语义被摧毁且不报错）。口径与 quoteScan.js 及其余已迁移插件一致。
        const _lit = readSqlLiteral(src, i, "'");
        if (!_lit.closed) { out += src.slice(i); return out; }
        inSingle = true; out += ch;
      }
      else if (ch === '"') {
        // [quoteScan] 未闭合字面量：原样透传剩余。原实现把尾部当普通字符逐个变换，
        // 对字面量编码型插件等于把 payload 尾部整个吃掉（SLEEP 关键字消失、
        // 注入语义被摧毁且不报错）。口径与 quoteScan.js 及其余已迁移插件一致。
        const _lit = readSqlLiteral(src, i, '"');
        if (!_lit.closed) { out += src.slice(i); return out; }
        inDouble = true; out += ch;
      }
      else if (/[a-zA-Z]/.test(ch) && Math.random() > 0.7) {
        // 30% 概率将字母编码为 CHAR()
        out += `CHAR(${ch.charCodeAt(0)})`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default randomascii;

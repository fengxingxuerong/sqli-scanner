// 空格 -> <span> 标签，绕过 WAF 空格过滤规则（对标 sqlmap space2span.py）
// 适用于 HTML 解析场景，利用 <span> 标签的空白字符绕过
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const space2span = {
  name: 'space2span',
  description: '将空格替换为 <span> 标签，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false, inLine = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (inLine) { out += ch; if (ch === '\n') inLine = false; continue; }
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
      else if (ch === '-' && src[i + 1] === '-') { inLine = true; out += ch; }
      else if (ch === ' ') out += '<span> </span>';
      else out += ch;
    }
    return out;
  },
};
export default space2span;

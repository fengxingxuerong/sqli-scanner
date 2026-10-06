// 多余括号移除：移除 SQL 中多余的括号（对标 sqlmap unparen.py）
// 适用于 WAF 对括号有检测规则的场景
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const unparen = {
  name: 'unparen',
  description: '移除 SQL 中多余的括号，绕过 WAF 对括号的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let depth = 0;
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
      else if (ch === '(') { depth++; if (depth > 1) out += ch; }
      else if (ch === ')') { if (depth > 1) out += ch; depth--; }
      else out += ch;
    }
    return out;
  },
};
export default unparen;

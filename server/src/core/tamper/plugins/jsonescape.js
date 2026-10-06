// JSON 转义：对字符串字面量内的 JSON 特殊字符做转义处理（对标 sqlmap jsonescape.py）
// 适用于 JSON API 场景
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const jsonescape = {
  name: 'jsonescape',
  description: '对字符串字面量中的 JSON 特殊字符做转义，绕过 JSON API WAF',
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
        else if (ch === '\\' || ch === '"' || ch === '\b' || ch === '\f' || ch === '\n' || ch === '\r' || ch === '\t') {
          out += '\\' + ch;
        } else {
          out += ch;
        }
        continue;
      }
      if (inDouble) {
        if (ch === '"' && !isQuoteEscaped(src, i)) { inDouble = false; out += ch; }
        else if (ch === '\\' || ch === '"' || ch === '\b' || ch === '\f' || ch === '\n' || ch === '\r' || ch === '\t') {
          out += '\\' + ch;
        } else {
          out += ch;
        }
        continue;
      }
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
      else out += ch;
    }
    return out;
  },
};
export default jsonescape;

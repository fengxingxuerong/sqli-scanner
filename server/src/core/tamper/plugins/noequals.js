// 相等 → LIKE 替换：将 = 替换为 LIKE，绕过 = 过滤规则（对标 sqlmap noequals.py）
// 适用于 WAF 对 = 符号有严格检测规则的场景
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const noequals = {
  name: 'noequals',
  description: '将 = 替换为 LIKE，绕过 WAF 对等号的过滤规则（引号保护）',
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
      const ch = src[i]
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
      else if (ch === '=') out += 'LIKE';
      else out += ch;
    }
    return out;
  },
};
export default noequals;

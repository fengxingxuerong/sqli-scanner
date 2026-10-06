// 反斜杠 -> 正斜杠，绕过路径过滤和 WAF 规则（对标 sqlmap backslash2forward.py）
import { isQuoteEscaped, readSqlLiteral } from '../quoteScan.js';
export const backslash2forward = {
  name: 'backslash2forward',
  description: '将反斜杠替换为正斜杠，绕过路径过滤（引号状态机保护字符串字面量）',
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
      else if (ch === '\\') out += '/';
      else out += ch;
    }
    return out;
  },
};
export default backslash2forward;

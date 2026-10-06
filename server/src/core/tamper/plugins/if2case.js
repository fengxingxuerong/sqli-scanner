// IF(A,B,C) → CASE WHEN (A) THEN (B) ELSE (C) END（对标 sqlmap if2case.py）
// 深度感知括号与引号，正确处理嵌套调用与字符串字面量，绕过对 IF() 的弱过滤。
const EMPTY_PAREN_MARKER = '\u0000'; // NUL 不会出现在合法 SQL 串，用于暂存空括号

// [2026-10-05] 引号判别改用 quoteScan 单一真源。
// 原写法 `s[i-1] !== '\\'` 问的是"前一个字符是不是反斜杠"，而正确判据是
// **连续反斜杠的奇偶性**：'a\' 的末位引号被转义（未闭合），'a\\' 的未转义（闭合）。
// 影响：遇到 'a\\' 时引号状态永不复位 → 该 IF( 之后的括号配对全盘算错 →
// 既漏掉本该转换的 IF()，也可能把 `)` 配到错误的位置。
import { isQuoteEscaped } from '../quoteScan.js';

export const if2case = {
  name: 'if2case',
  description: '将 IF(A,B,C) 改写为 CASE WHEN (A) THEN (B) ELSE (C) END，绕过 IF 函数过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    if (!s.includes('IF(')) return s;
    s = s.replaceAll('()', EMPTY_PAREN_MARKER);
    while (s.includes('IF(')) {
      const index = s.indexOf('IF(');
      let depth = 1;
      let inSingle = false;
      let inDouble = false;
      const commas = [];
      let end = -1;
      for (let i = index + 3; i < s.length; i++) {
        const ch = s[i];
        if (ch === "'" && !isQuoteEscaped(s, i)) inSingle = !inSingle;
        else if (ch === '"' && !isQuoteEscaped(s, i)) inDouble = !inDouble;
        if (inSingle || inDouble) continue;
        if (depth === 1 && ch === ',') commas.push(i);
        else if (depth === 1 && ch === ')') {
          end = i;
          break;
        } else if (ch === '(') depth++;
        else if (ch === ')') depth--;
      }
      if (commas.length === 2 && end > -1) {
        const stripParens = (t) => t.trim().replace(/^\(+|\)+$/g, '');
        const a = stripParens(s.slice(index + 3, commas[0]));
        const b = stripParens(s.slice(commas[0] + 1, commas[1]));
        const c = stripParens(s.slice(commas[1] + 1, end));
        s = s.slice(0, index) + `CASE WHEN (${a}) THEN (${b}) ELSE (${c}) END` + s.slice(end + 1);
      } else {
        break;
      }
    }
    return s.replaceAll(EMPTY_PAREN_MARKER, '()');
  },
};

export default if2case;

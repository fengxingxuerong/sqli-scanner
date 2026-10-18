// '+' 拼接 → MsSQL ODBC {fn CONCAT()} 嵌套调用（对标 sqlmap plus2fnconcat.py）
// 改写为左嵌套的 {fn CONCAT({fn CONCAT(a,b)},c)} 形式。
//
// [D107 2026-10-18] 手写 inQuote 迷你循环迁移到 literalWalk 单一抽象（同 plus2concat）：
// 反斜杠转义引号不再翻错；双引号字面量与行注释内的 + 不再被误切分。
// A/B 对拍留痕：仅上述三类输入出现差异，其余逐字节一致（见 CHANGELOG D107）。
import { walkLiterals } from '../literalWalk.js';

const SPLIT_MARK = '\u0002'; // 合法 SQL 文本不含：顶层 + 的哨兵，组合后再切分

export const plus2fnconcat = {
  name: 'plus2fnconcat',
  description: '将 + 拼接改写为 MsSQL ODBC {fn CONCAT()} 嵌套调用，绕过加号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/('[^']+'|CHAR\(\d+\))\+.*\+('[^']+'|CHAR\(\d+\))/i, (whole) => {
      let depth = 0;
      const composed = walkLiterals(whole, {
        onText: (text) => {
          let out = '';
          for (const ch of text) {
            if (ch === '(') depth += 1;
            else if (ch === ')') depth -= 1;
            if (ch === '+' && depth === 0) {
              out += SPLIT_MARK;
              continue;
            }
            out += ch;
          }
          return out;
        },
      });
      const parts = composed.split(SPLIT_MARK);
      let replacement = parts[0];
      for (let i = 1; i < parts.length; i++) {
        replacement = `{fn CONCAT(${replacement},${parts[i]})}`;
      }
      return replacement;
    });
  },
};

export default plus2fnconcat;

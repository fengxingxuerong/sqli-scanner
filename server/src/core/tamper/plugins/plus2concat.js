// '+' 拼接 → MsSQL CONCAT() 函数（对标 sqlmap plus2concat.py）
// 仅改写「字符串字面量 / CHAR(n)」参与的首尾拼接段，顶层 + 换为逗号并包裹 CONCAT()。
//
// [D107 2026-10-18] 手写 inQuote 迷你循环迁移到 literalWalk 单一抽象：
//   · 旧逻辑遇 `'` 就翻转（无奇偶性判据）—— `'it\'s'+x` 这类反斜杠转义引号会翻错；
//     迁移后字面量由 readSqlLiteral 读取，转义/双写引号都留在字面量内（修正）。
//   · 旧逻辑不识别双引号字面量内部 —— `"a+b"` 里的 + 会被误换成逗号；迁移后整体跳过。
//   · 行注释（-- ...）内的 + 不再被改写。
//   A/B 对拍留痕：以上三类输入出现差异，其余输入逐字节一致（见 CHANGELOG D107）。
import { walkLiterals } from '../literalWalk.js';

export const plus2concat = {
  name: 'plus2concat',
  description: '将 + 拼接改写为 MsSQL CONCAT() 函数，绕过加号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/('[^']+'|CHAR\(\d+\))\+.*\+('[^']+'|CHAR\(\d+\))/i, (whole) => {
      let depth = 0;
      const inner = walkLiterals(whole, {
        onText: (text) => {
          let out = '';
          for (const ch of text) {
            if (ch === '(') depth += 1;
            else if (ch === ')') depth -= 1;
            else if (ch === '+' && depth === 0) {
              out += ',';
              continue;
            }
            out += ch;
          }
          return out;
        },
        onLiteral: (body, quote) => quote + body + quote,
      });
      return `CONCAT(${inner})`;
    });
  },
};

export default plus2concat;

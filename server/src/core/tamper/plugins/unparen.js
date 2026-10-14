// 多余括号移除：移除 SQL 中多余的括号（对标 sqlmap unparen.py）
// 最外层括号剥掉（depth 归 1 的那对），内层保留；引号内括号是数据，不参与配对。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
// 注意：depth 状态跨段保持（onText 按段回调，字面量段不参与配对）。
import { walkLiterals } from '../literalWalk.js';

export const unparen = {
  name: 'unparen',
  description: '移除 SQL 中多余的括号，绕过 WAF 对括号的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let depth = 0;
    return walkLiterals(payload, {
      onText: (t) => {
        let out = '';
        for (const ch of t) {
          if (ch === '(') { depth++; if (depth > 1) out += ch; }
          else if (ch === ')') { if (depth > 1) out += ch; depth--; }
          else out += ch;
        }
        return out;
      },
    });
  },
};
export default unparen;

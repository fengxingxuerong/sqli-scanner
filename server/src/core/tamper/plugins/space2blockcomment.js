// 空格 → MySQL 条件注释：将空格替换为 /*! 注释 */（对标 sqlmap space2blockcomment.py）
// MySQL 条件注释内的语句仍会被执行
import { walkLiterals } from '../literalWalk.js';

export const space2blockcomment = {
  name: 'space2blockcomment',
  description: '将空格替换为 MySQL 条件注释 /*! */，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '/*!*/'),
    });
  },
};
export default space2blockcomment;

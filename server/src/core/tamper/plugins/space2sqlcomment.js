// 空格 → SQL 行注释 #：将空格替换为 SQL 行注释 #（对标 sqlmap space2sqlcomment.py）
import { walkLiterals } from '../literalWalk.js';

export const space2sqlcomment = {
  name: 'space2sqlcomment',
  description: '将空格替换为 SQL 行注释 #，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '#'),
    });
  },
};
export default space2sqlcomment;

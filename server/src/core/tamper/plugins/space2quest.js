// 空格 → 问号：将空格替换为问号 ?（对标 sqlmap space2quest.py）
import { walkLiterals } from '../literalWalk.js';

export const space2quest = {
  name: 'space2quest',
  description: '将空格替换为问号 ?，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '?'),
    });
  },
};
export default space2quest;

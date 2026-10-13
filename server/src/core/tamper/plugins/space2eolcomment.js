// 空格 → 行尾注释：将空格替换为行尾注释 -- （对标 sqlmap space2eolcomment.py）
import { walkLiterals } from '../literalWalk.js';

export const space2eolcomment = {
  name: 'space2eolcomment',
  description: '将空格替换为行尾注释 --，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '--'),
    });
  },
};
export default space2eolcomment;

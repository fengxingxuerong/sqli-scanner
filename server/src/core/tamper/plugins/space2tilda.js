// 空格 → 波浪线：将空格替换为波浪线 ~（对标 sqlmap space2tilda.py）
import { walkLiterals } from '../literalWalk.js';

export const space2tilda = {
  name: 'space2tilda',
  description: '将空格替换为波浪线 ~，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '~'),
    });
  },
};
export default space2tilda;

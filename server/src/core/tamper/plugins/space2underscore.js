// 空格 → 下划线：将空格替换为下划线 _（对标 sqlmap space2underscore.py）
import { walkLiterals } from '../literalWalk.js';

export const space2underscore = {
  name: 'space2underscore',
  description: '将空格替换为下划线 _，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '_'),
    });
  },
};
export default space2underscore;

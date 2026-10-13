// 空格 → 竖线：将空格替换为竖线 |（对标 sqlmap space2pipe.py）
import { walkLiterals } from '../literalWalk.js';

export const space2pipe = {
  name: 'space2pipe',
  description: '将空格替换为竖线 |，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '|'),
    });
  },
};
export default space2pipe;

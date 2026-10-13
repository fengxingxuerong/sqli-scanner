// 空格 → 感叹号：将空格替换为感叹号 !（对标 sqlmap space2excl.py）
import { walkLiterals } from '../literalWalk.js';

export const space2excl = {
  name: 'space2excl',
  description: '将空格替换为感叹号 !，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '!'),
    });
  },
};
export default space2excl;

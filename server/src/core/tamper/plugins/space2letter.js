// 空格 → 随机字母：将空格替换为随机字母（对标 sqlmap space2letter.py）
const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
import { walkLiterals } from '../literalWalk.js';

export const space2letter = {
  name: 'space2letter',
  description: '将空格替换为随机字母，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, () => letters[Math.floor(Math.random() * letters.length)]),
    });
  },
};
export default space2letter;

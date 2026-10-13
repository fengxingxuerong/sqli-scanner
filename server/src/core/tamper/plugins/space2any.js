// 空格 → 随机可见字符：将空格替换为随机 ASCII 可见字符（对标 sqlmap space2any.py）
const CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
import { walkLiterals } from '../literalWalk.js';

export const space2any = {
  name: 'space2any',
  description: '将空格替换为随机可见字符，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, () => CHARS[Math.floor(Math.random() * CHARS.length)]),
    });
  },
};
export default space2any;

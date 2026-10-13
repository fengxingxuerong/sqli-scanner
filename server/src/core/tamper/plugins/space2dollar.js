// 空格 → 美元符号：将空格替换为 $ 符号（对标 sqlmap space2dollar.py）
import { walkLiterals } from '../literalWalk.js';

export const space2dollar = {
  name: 'space2dollar',
  description: '将空格替换为美元符号 $，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '$'),
    });
  },
};
export default space2dollar;

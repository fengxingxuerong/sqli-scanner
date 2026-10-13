// 空格 -> <span> 标签，绕过 WAF 空格过滤规则（对标 sqlmap space2span.py）
// 适用于 HTML 解析场景，利用 <span> 标签的空白字符绕过
import { walkLiterals } from '../literalWalk.js';

export const space2span = {
  name: 'space2span',
  description: '将空格替换为 <span> 标签，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) => t.replace(/ /g, '<span> </span>'),
    });
  },
};
export default space2span;

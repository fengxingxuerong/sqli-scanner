// 动态 payload：随机大小写化每个字母（对标 sqlmap dpayload.py）
// 比 randomcase 更激进：每个字母独立随机大小写。引号内原样透传。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const dpayload = {
  name: 'dpayload',
  description: '动态大小写混淆每个字母，绕过 WAF 关键字检测（比 randomcase 更激进）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return walkLiterals(payload, {
      onText: (t) =>
        t.replace(/[a-zA-Z]/g, (c) => (Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase())),
    });
  },
};
export default dpayload;

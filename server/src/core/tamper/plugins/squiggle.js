// 波浪线编码：在关键字之间插入波浪线符号（对标 sqlmap squiggle.py）
// 适用于某些对波浪线处理不当的 WAF
export const squiggle = {
  name: 'squiggle',
  description: '在关键字之间插入波浪线符号，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL~~ECT' : 'sel~~ect')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN~~ION' : 'un~~ion')
      .replace(/\bAND\b/gi, (m) => m[0] === 'A' ? 'AN~~D' : 'an~~d');
  },
};
export default squiggle;

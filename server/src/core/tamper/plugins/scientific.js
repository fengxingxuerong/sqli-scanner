// 科学计数法编码：将数字编码为科学计数法形式（对标 sqlmap scientific.py）
// 适用于 WAF 对数字有检测规则的场景
export const scientific = {
  name: 'scientific',
  description: '将数字编码为科学计数法形式，绕过 WAF 对数字的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 1 && n <= 99999) {
        // 用科学计数法表示
        const exp = Math.floor(Math.log10(n));
        const mantissa = n / Math.pow(10, exp);
        return `${mantissa.toFixed(1)}e${exp}`;
      }
      return match;
    });
  },
};
export default scientific;

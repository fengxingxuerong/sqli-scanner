// 随机数字替换：将数字随机替换为数学表达式（对标 sqlmap randomdigit.py）
// 例如：1 → 2-1, 3 → 2+1, 5 → 10/2
export const randomdigit = {
  name: 'randomdigit',
  description: '将数字随机替换为数学表达式，绕过 WAF 对数字的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const expressions = [
      (n) => `${n + 1}-1`,
      (n) => `${n + 0}+0`,
      (n) => `${n + 2}-2`,
      (n) => `${n * 2}/2`,
      (n) => `${n + 3}-3`,
    ];
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 0 && n <= 999 && Math.random() > 0.5) {
        const pick = expressions[Math.floor(Math.random() * expressions.length)];
        return pick(n);
      }
      return match;
    });
  },
};
export default randomdigit;

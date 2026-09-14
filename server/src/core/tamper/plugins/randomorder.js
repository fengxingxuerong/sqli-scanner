// 随机 ORDER BY 格式：随机化 ORDER BY 子句格式（对标 sqlmap randomorder.py）
// 将 ORDER BY 1 替换为 ORDER BY 1+0, ORDER BY 1-0 等
export const randomorder = {
  name: 'randomorder',
  description: '随机化 ORDER BY 子句格式，绕过 WAF 对 ORDER BY 的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const variants = [
      (m, num) => `${m}${num}`,
      (m, num) => `${m}${num}+0`,
      (m, num) => `${m}${num}-0`,
      (m, num) => `${m}${num}^0`,
      (m, num) => `${m}${num}|0`,
    ];
    const pick = variants[Math.floor(Math.random() * variants.length)];
    return String(payload ?? '').replace(/(ORDER\s+BY\s+)(\d+)/gi, (match, prefix, num) => {
      const isUpper = prefix[0] === 'O';
      const p = isUpper ? prefix.toUpperCase() : prefix.toLowerCase();
      return pick(p, num);
    });
  },
};
export default randomorder;

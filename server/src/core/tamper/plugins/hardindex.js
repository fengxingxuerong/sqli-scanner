// 硬编码索引：将数字索引替换为硬编码的 ASCII 字符（对标 sqlmap hardindex.py）
// 适用于 WAF 对数字索引有检测规则的场景
export const hardindex = {
  name: 'hardindex',
  description: '将数字索引替换为 ASCII 字符编码，绕过 WAF 对数字索引的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 0 && n <= 9) {
        // 0-9 用 CHAR 编码
        return `CHAR(${n + 48})`;
      }
      return match;
    });
  },
};
export default hardindex;

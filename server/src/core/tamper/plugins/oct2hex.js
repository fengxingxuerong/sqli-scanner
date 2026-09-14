// 八进制 → 十六进制：将八进制数字转换为十六进制（对标 sqlmap oct2hex.py）
export const oct2hex = {
  name: 'oct2hex',
  description: '将八进制数字转换为十六进制表示，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/(\d+)o/g, (match, num) => {
      try {
        const dec = parseInt(num, 8);
        return `0x${dec.toString(16)}`;
      } catch { return match; }
    });
  },
};
export default oct2hex;

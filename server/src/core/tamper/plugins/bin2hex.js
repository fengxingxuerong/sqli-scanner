// 二进制 → 十六进制：将二进制数字转换为十六进制（对标 sqlmap bin2hex.py）
export const bin2hex = {
  name: 'bin2hex',
  description: '将二进制数字转换为十六进制表示，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/0b([01]+)/g, (match, bin) => {
      try {
        const dec = parseInt(bin, 2);
        return `0x${dec.toString(16)}`;
      } catch { return match; }
    });
  },
};
export default bin2hex;

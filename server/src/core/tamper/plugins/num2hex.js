// 数字 → 十六进制 CHAR()：将数字替换为十六进制 CHAR() 调用（对标 sqlmap num2hex.py）
// 例如：1 → CHAR(0x31)
export const num2hex = {
  name: 'num2hex',
  description: '将数字替换为十六进制 CHAR() 调用，绕过 WAF 对数字的检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 0 && n <= 99999) {
        const hex = n.toString(16);
        return `CHAR(0x${hex})`;
      }
      return match;
    });
  },
};
export default num2hex;
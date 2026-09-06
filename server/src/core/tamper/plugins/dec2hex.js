// 十进制 → 十六进制：将十进制数字转换为十六进制（对标 sqlmap dec2hex.py）
export const dec2hex = {
  name: 'dec2hex',
  description: '将十进制数字转换为十六进制表示，绕过 WAF 检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 0 && n <= 99999) {
        return `0x${n.toString(16)}`;
      }
      return match;
    });
  },
};
export default dec2hex;
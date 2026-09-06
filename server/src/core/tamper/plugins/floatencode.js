// 浮点编码：将整数编码为浮点数表示（对标 sqlmap floatencode.py）
// 例如：1 → 1.0, 2 → 2.0, 0 → 0.0
export const floatencode = {
  name: 'floatencode',
  description: '将整数编码为浮点数表示，绕过 WAF 对整数的检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\b(\d+)\b/g, (match, num) => {
      const n = parseInt(num, 10);
      if (n >= 0 && n <= 999999) {
        return `${n}.0`;
      }
      return match;
    });
  },
};
export default floatencode;
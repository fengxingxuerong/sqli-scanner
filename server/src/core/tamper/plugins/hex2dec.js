// 十六进制 → 十进制：将十六进制数字转换为十进制（对标 sqlmap hex2dec.py）
// 适用于 WAF 对十六进制有检测规则的场景
export const hex2dec = {
  name: 'hex2dec',
  description: '将十六进制数字转换为十进制，绕过 WAF 对十六进制的检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/0x([0-9a-fA-F]+)/g, (match, hex) => {
      try {
        return String(parseInt(hex, 16));
      } catch {
        return match;
      }
    });
  },
};
export default hex2dec;
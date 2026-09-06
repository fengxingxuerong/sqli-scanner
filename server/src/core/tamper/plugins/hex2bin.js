// 十六进制 → 二进制：将十六进制数字转换为二进制（对标 sqlmap hex2bin.py）
export const hex2bin = {
  name: 'hex2bin',
  description: '将十六进制数字转换为二进制表示，绕过 WAF 检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/0x([0-9a-fA-F]+)/g, (match, hex) => {
      try {
        const dec = parseInt(hex, 16);
        return `0b${dec.toString(2)}`;
      } catch { return match; }
    });
  },
};
export default hex2bin;
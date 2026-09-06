// DHS 安全设备绕过：在关键字之间插入 DHS 特定的注释（对标 sqlmap dhs.py）
export const dhs = {
  name: 'dhs',
  description: 'DHS 安全设备 WAF 绕过：在关键字之间插入 DHS 特定注释',
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bAND\b/gi, (m) => m[0] === 'A' ? 'AN/**/D' : 'an/**/d')
      .replace(/\bOR\b/gi, (m) => m[0] === 'O' ? 'O/**/R' : 'o/**/r')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL/**/ECT' : 'sel/**/ect');
  },
};
export default dhs;
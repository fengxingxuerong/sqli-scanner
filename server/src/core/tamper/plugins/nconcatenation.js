// 禁用 CONCAT 拼接：将 CONCAT() 替换为多个参数拼接（对标 sqlmap nconcatenation.py）
// 适用于 WAF 对 CONCAT 函数有检测规则的场景
export const nconcatenation = {
  name: 'nconcatenation',
  description: '将 CONCAT() 替换为参数拼接，绕过 WAF 对 CONCAT 的检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/CONCAT\s*\(/gi, (match) => {
      return match[0] === 'C' ? 'CONCAT_WS(0x0,' : 'concat_ws(0x0,';
    });
  },
};
export default nconcatenation;
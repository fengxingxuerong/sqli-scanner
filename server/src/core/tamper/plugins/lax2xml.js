// LAX → XML 转换：将 SQL 查询中的 LAX 函数替换为 XML 函数（对标 sqlmap lax2xml.py）
// 适用于 WAF 对 LAX 关键词有检测规则的场景
export const lax2xml = {
  name: 'lax2xml',
  description: '将 LAX 函数替换为 XML 函数，绕过 WAF 对 LAX 关键词的检测',
  transform(payload, ctx) {
    let s = String(payload ?? '');
    s = s.replace(/\bLAX\b/gi, (m) => m[0] === 'L' ? 'XML' : 'xml');
    return s;
  },
};
export default lax2xml;
// 随机边界符：在关键字之间插入随机边界符（对标 sqlmap randomboundary.py）
const BOUNDARIES = ['/**/', '/*!*/', '--', '#', '/*', '*/'];

export const randomboundary = {
  name: 'randomboundary',
  description: '在关键字之间插入随机边界符，绕过 WAF 关键字检测',
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
    let s = String(payload ?? '');
    for (const kw of keywords) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, (match) => {
        const boundary = BOUNDARIES[Math.floor(Math.random() * BOUNDARIES.length)];
        return `${match}${boundary}`;
      });
    }
    return s;
  },
};
export default randomboundary;
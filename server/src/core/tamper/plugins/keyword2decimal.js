// 关键字 → 十进制：将 SQL 关键字编码为十进制数字序列（对标 sqlmap keyword2decimal.py）
export const keyword2decimal = {
  name: 'keyword2decimal',
  description: '将 SQL 关键字编码为十进制数字序列，绕过 WAF 关键字检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
    let s = String(payload ?? '');
    for (const kw of keywords) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, (match) => {
        return match.toLowerCase().split('').map(c => String(c.charCodeAt(0))).join(' ');
      });
    }
    return s;
  },
};
export default keyword2decimal;
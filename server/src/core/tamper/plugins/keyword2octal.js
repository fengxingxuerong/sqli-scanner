// 关键字 → 八进制：将 SQL 关键字编码为八进制表示（对标 sqlmap keyword2octal.py）
export const keyword2octal = {
  name: 'keyword2octal',
  description: '将 SQL 关键字编码为八进制表示，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
    let s = String(payload ?? '');
    for (const kw of keywords) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, (match) => {
        return match.toLowerCase().split('').map(c => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`).join('');
      });
    }
    return s;
  },
};
export default keyword2octal;

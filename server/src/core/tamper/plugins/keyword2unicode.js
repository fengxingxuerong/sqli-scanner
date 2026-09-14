// 关键字 → Unicode 编码：将关键字中的字母用 Unicode 编码（对标 sqlmap keyword2unicode.py）
// 例如：SELECT → \u0053\u0045\u004C\u0045\u0043\u0054
export const keyword2unicode = {
  name: 'keyword2unicode',
  description: '将 SQL 关键字中的字母用 Unicode 编码，绕过 WAF 关键字检测',
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
        return match.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
      });
    }
    return s;
  },
};
export default keyword2unicode;

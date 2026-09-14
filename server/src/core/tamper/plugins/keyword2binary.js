// 关键字 → 二进制：将 SQL 关键字编码为二进制 0b 表示（对标 sqlmap keyword2binary.py）
export const keyword2binary = {
  name: 'keyword2binary',
  description: '将 SQL 关键字编码为二进制 0b 表示，绕过 WAF 关键字检测',
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
        const bin = match.toLowerCase().split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('');
        return `0b${bin}`;
      });
    }
    return s;
  },
};
export default keyword2binary;

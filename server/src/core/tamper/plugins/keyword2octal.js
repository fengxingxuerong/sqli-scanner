// 关键字 → 八进制：将 SQL 关键字编码为八进制表示（对标 sqlmap keyword2octal.py）
// [2026-10-12 性能] 关键字表与正则模块级预编译（原 transform 内 16 次 new RegExp/call，
// 零行为变化；论证见 keyword2hex.js 同批注释）
const KEYWORDS = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
const RES = KEYWORDS.map((kw) => new RegExp(`\\b${kw}\\b`, 'gi'));

export const keyword2octal = {
  name: 'keyword2octal',
  description: '将 SQL 关键字编码为八进制表示，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    for (const re of RES) {
      s = s.replace(re, (match) => {
        return match.toLowerCase().split('').map(c => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`).join('');
      });
    }
    return s;
  },
};
export default keyword2octal;

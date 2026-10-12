// 关键字 → 十进制：将 SQL 关键字编码为十进制数字序列（对标 sqlmap keyword2decimal.py）
// [2026-10-12 性能] 关键字表与正则模块级预编译（原 transform 内 16 次 new RegExp/call，
// 零行为变化；论证见 keyword2hex.js 同批注释）
const KEYWORDS = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
const RES = KEYWORDS.map((kw) => new RegExp(`\\b${kw}\\b`, 'gi'));

export const keyword2decimal = {
  name: 'keyword2decimal',
  description: '将 SQL 关键字编码为十进制数字序列，绕过 WAF 关键字检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    for (const re of RES) {
      s = s.replace(re, (match) => {
        return match.toLowerCase().split('').map(c => String(c.charCodeAt(0))).join(' ');
      });
    }
    return s;
  },
};
export default keyword2decimal;

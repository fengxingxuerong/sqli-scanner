// 随机边界符：在关键字之间插入随机边界符（对标 sqlmap randomboundary.py）
const BOUNDARIES = ['/**/', '/*!*/', '--', '#', '/*', '*/'];

// [2026-10-12 性能] 关键字表与正则模块级预编译（原 transform 内 16 次 new RegExp/call，
// 零行为变化；论证见 keyword2hex.js 同批注释）
const KEYWORDS = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET'];
const RES = KEYWORDS.map((kw) => new RegExp(`\\b${kw}\\b`, 'gi'));

export const randomboundary = {
  name: 'randomboundary',
  description: '在关键字之间插入随机边界符，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    for (const re of RES) {
      s = s.replace(re, (match) => {
        const boundary = BOUNDARIES[Math.floor(Math.random() * BOUNDARIES.length)];
        return `${match}${boundary}`;
      });
    }
    return s;
  },
};
export default randomboundary;

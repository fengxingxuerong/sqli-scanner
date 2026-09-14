// 访问过滤器绕过：在关键字之间插入访问过滤器特定的注释（对标 sqlmap accessfilter.py）
export const accessfilter = {
  name: 'accessfilter',
  description: '访问过滤器 WAF 绕过：在关键字之间插入特殊注释标记',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL/**/ECT' : 'sel/**/ect')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN/**/ION' : 'un/**/ion')
      .replace(/\bWHERE\b/gi, (m) => m[0] === 'W' ? 'WH/**/ERE' : 'wh/**/ere')
      .replace(/\bAND\b/gi, (m) => m[0] === 'A' ? 'AN/**/D' : 'an/**/d')
      .replace(/\bOR\b/gi, (m) => m[0] === 'O' ? 'O/**/R' : 'o/**/r');
  },
};
export default accessfilter;

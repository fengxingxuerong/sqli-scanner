// ASP/Jetty 特定绕过：在关键字之间插入 ASP/Jetty 注释（对标 sqlmap aspjetty.py）
export const aspjetty = {
  name: 'aspjetty',
  description: 'ASP/Jetty WAF 绕过：在关键字之间插入 ASP 注释标记',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN%00ION' : 'un%00ion')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL%00ECT' : 'sel%00ect');
  },
};
export default aspjetty;

// ASP 响应投递：在 payload 中嵌入 ASP 响应投递标记（对标 sqlmap aspdelivery.py）
// 适用于 ASP.NET 后端的 WAF 绕过
export const aspdelivery = {
  name: 'aspdelivery',
  description: '在 payload 中嵌入 ASP 响应投递标记，绕过 ASP.NET WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    // 在 SELECT 关键字前后添加 ASP 标记
    return src.replace(/\bSELECT\b/gi, (m) => {
      const isUpper = m[0] === 'S';
      return isUpper ? '<%SELECT%>' : '<%select%>';
    });
  },
};
export default aspdelivery;

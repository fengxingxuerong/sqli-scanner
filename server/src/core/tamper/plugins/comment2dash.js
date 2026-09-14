// 注释 → 短横线：将内联注释 /**/ 替换为短横线 --（对标 sqlmap comment2dash.py）
export const comment2dash = {
  name: 'comment2dash',
  description: '将内联注释 /**/ 替换为短横线 --，绕过 WAF 对注释的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\/\*[\s\S]*?\*\//g, '--');
  },
};
export default comment2dash;

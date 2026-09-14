// 换行符 → 注释：将换行符替换为内联注释 /**/（对标 sqlmap newline2comment.py）
export const newline2comment = {
  name: 'newline2comment',
  description: '将换行符替换为内联注释 /**/，绕过 WAF 对换行符的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\n/g, '/**/');
  },
};
export default newline2comment;

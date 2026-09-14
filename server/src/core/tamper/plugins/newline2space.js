// 换行符 → 空格：将换行符替换为空格（对标 sqlmap newline2space.py）
export const newline2space = {
  name: 'newline2space',
  description: '将换行符替换为空格，绕过 WAF 对换行符的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\n/g, ' ');
  },
};
export default newline2space;

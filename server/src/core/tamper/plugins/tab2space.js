// 制表符 → 空格：将制表符替换为空格（对标 sqlmap tab2space.py）
export const tab2space = {
  name: 'tab2space',
  description: '将制表符替换为空格，绕过 WAF 对制表符的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\t/g, ' ');
  },
};
export default tab2space;

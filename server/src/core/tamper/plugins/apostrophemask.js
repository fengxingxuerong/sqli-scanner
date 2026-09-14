// 单引号转 UTF-8 全角引号（%EF%BC%87），绕过基于单引号的 WAF 关键字
export const apostrophemask = {
  name: 'apostrophemask',
  description: "将单引号 ' 替换为 UTF-8 全角形式 %EF%BC%87，绕过引号过滤",
  doctests: [
    { input: "a'b", output: 'a%EF%BC%87b' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/'/g, '%EF%BC%87');
  },
};
export default apostrophemask;

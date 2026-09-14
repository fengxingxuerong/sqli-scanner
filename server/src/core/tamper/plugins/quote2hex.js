// 单引号字符串字面量转 0x 十六进制（如 'abc'→0x616263），避免字面引号
export const quote2hex = {
  name: 'quote2hex',
  description: "将单引号字符串字面量（'...'）转为 0x 十六进制形式，避免字面引号",
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/'([^']*)'/g, (m, p1) =>
      '0x' + [...p1].map((c) => c.charCodeAt(0).toString(16)).join(''));
  },
};
export default quote2hex;

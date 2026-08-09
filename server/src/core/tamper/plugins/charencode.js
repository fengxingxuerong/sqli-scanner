// 字符 URL/十六进制编码（类名 charencode）
// 对空格与特殊字符做 URL 编码，绕过关键字/符号过滤。
export const charencode = {
  name: 'charencode',
  description: '对空格与特殊字符做 URL 编码，绕过符号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    // 字母数字与下划线保留，其余（空格、引号、括号、注释符等）做 URL 编码
    return payload.replace(/[^a-zA-Z0-9_]/g, (ch) => encodeURIComponent(ch));
  },
};

export default charencode;

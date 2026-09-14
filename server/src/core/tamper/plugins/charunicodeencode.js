// 将字母字符编码为 %uXXXX（Unicode/宽字节注入绕过）。
// 目标在解码参数时会还原为原字符；对只做关键字字面匹配的 WAF 可绕过。
// 注：会对整串字母编码，且对数字/符号不变；需目标侧做 URL 解码，按需搭配使用。
export const charunicodeencode = {
  name: 'charunicodeencode',
  description: '将字母字符编码为 %uXXXX（宽字节/Unicode 注入绕过）',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/[A-Za-z]/g, (c) => '%u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  },
};

export default charunicodeencode;

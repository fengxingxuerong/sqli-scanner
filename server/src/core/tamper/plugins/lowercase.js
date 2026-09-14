// 将 Payload 全部转为小写，绕过只拦截大写关键字的 WAF（与 randomcase 的随机风格互补）。
export const lowercase = {
  name: 'lowercase',
  description: '将 Payload 全部转为小写（绕过只拦截大写关键字的 WAF）',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.toLowerCase();
  },
};

export default lowercase;

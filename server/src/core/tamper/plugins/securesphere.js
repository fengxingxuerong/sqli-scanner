// 追加 SecureSphere 特定标记注释，绕过 Imperva SecureSphere WAF 的签名
export const securesphere = {
  name: 'securesphere',
  description: '在 payload 末尾追加 /*!ANN0*/ 标记，绕过 SecureSphere 类签名',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload + '/*!ANN0*/';
  },
};
export default securesphere;

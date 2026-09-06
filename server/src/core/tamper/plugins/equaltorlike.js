// 等号 -> RLIKE（对标 sqlmap equaltorlike.py）
// 把比较运算符 `=` 替换为 RLIKE，等价语义下绕过 `=` 关键字过滤。
export const equaltorlike = {
  name: 'equaltorlike',
  description: '将等号 = 替换为 RLIKE，等价语义绕过等号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/=/g, 'RLIKE');
  },
};

export default equaltorlike;

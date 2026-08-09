// 等号 -> LIKE（类名 equaltolike）
// 把比较运算符 `=` 替换为 `LIKE`，等价语义下绕过 `=` 关键字过滤。
export const equaltolike = {
  name: 'equaltolike',
  description: '将等号 = 替换为 LIKE，等价语义绕过等号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/=/g, 'LIKE');
  },
};

export default equaltolike;

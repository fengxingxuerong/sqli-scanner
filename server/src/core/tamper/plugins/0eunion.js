// <数字> UNION → <数字>e0UNION（对标 sqlmap 0eunion.py）
// 在整数与 UNION 之间插入 e0，利用 MySQL/MsSQL 对科学计数法数字的解析绕过 UNION 字面过滤。
// 注：JS 标识符不能以数字开头，故导出常量为 eunion（name 字段仍为 '0eunion'）。
export const eunion = {
  name: '0eunion',
  description: '将 <数字> UNION 改写为 <数字>e0UNION，绕过 UNION 字面过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/(\d+)\s+(UNION )/gi, '$1e0$2');
  },
};

export default eunion;

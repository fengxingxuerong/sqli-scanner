// FROM 库表标识拆分（对标 sqlmap schemasplit.py）
// 将 `FROM <schema>.<table>` 中的点号替换为 ` 9.e.`（testdb.users → testdb 9.e.users），
// 利用 MySQL 对数字字面量后接标识符的容错解析绕过 schema 标识过滤。
export const schemasplit = {
  name: 'schemasplit',
  description: '拆分 FROM 库表标识中的点号（testdb.users → testdb 9.e.users）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/( FROM \w+)\.(\w+)/gi, '$1 9.e.$2');
  },
};

export default schemasplit;

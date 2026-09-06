// SQL 关键字表（共享常量，供 randomcase / space2morehash 等插件按关键字语义处理）
// 对标 sqlmap lib/core/settings.py 的 keyword 集合（覆盖常见 DML/DDL/函数/操作符关键字）。
// 全大写存储，判断时 word.toUpperCase() 后查表。
export const SQL_KEYWORDS = new Set([
  // 查询 / 子句
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'EXISTS', 'BETWEEN', 'LIKE', 'RLIKE',
  'REGEXP', 'IS', 'ISNULL', 'NULL', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET',
  'UNION', 'ALL', 'DISTINCT', 'DISTINCTROW', 'AS', 'ASC', 'DESC', 'TOP', 'JOIN', 'INNER',
  'LEFT', 'RIGHT', 'FULL', 'OUTER', 'CROSS', 'ON', 'USING', 'NATURAL', 'STRAIGHT_JOIN',
  'INTO', 'VALUES', 'SET', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'TRUNCATE', 'MERGE',
  'CREATE', 'ALTER', 'DROP', 'RENAME', 'GRANT', 'REVOKE', 'COMMENT',
  // 条件 / 控制流
  'IF', 'IFNULL', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'COALESCE', 'NULLIF', 'IIF',
  'WHILE', 'FOR', 'LOOP', 'DO', 'DECLARE', 'BEGIN', 'RETURN', 'BREAK', 'CONTINUE', 'GOTO',
  // 函数（常用聚合/字符串/数学/日期）
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'CONCAT', 'CONCAT_WS', 'SUBSTR', 'SUBSTRING',
  'MID', 'CHAR', 'ASCII', 'ORD', 'LENGTH', 'CHAR_LENGTH', 'LOWER', 'UPPER', 'UCASE', 'LCASE',
  'TRIM', 'LTRIM', 'RTRIM', 'REPLACE', 'REVERSE', 'LEFT', 'RIGHT', 'LOCATE', 'POSITION',
  'ABS', 'ROUND', 'FLOOR', 'CEIL', 'CEILING', 'POWER', 'SQRT', 'MOD', 'RAND',
  'NOW', 'SYSDATE', 'CURDATE', 'CURTIME', 'DATE', 'TIME', 'YEAR', 'MONTH', 'DAY', 'HOUR',
  'MINUTE', 'SECOND', 'CAST', 'CONVERT', 'GROUP_CONCAT', 'VERSION', 'DATABASE', 'USER',
  'CURRENT_USER', 'SYSTEM_USER', 'SESSION_USER', 'LOAD_FILE', 'SLEEP', 'BENCHMARK',
  'PG_SLEEP', 'EXTRACTVALUE', 'UPDATEXML',
  // [sqlmap 对标补齐] MSSQL 专属（r3 复审缺口）：versioned*/randomcase* 等
  // 关键字型 tamper 此前不识别 WAITFOR/XP_CMDSHELL → MSSQL 变换覆盖面缺失
  'WAITFOR', 'DELAY', 'XP_CMDSHELL', 'EXEC', 'EXECUTE', 'SP_EXECUTESQL',
  // 数据定义 / 对象
  'TABLE', 'DATABASE', 'SCHEMA', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION', 'TRIGGER',
  'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES', 'CONSTRAINT', 'DEFAULT', 'UNIQUE', 'CHECK',
  'PRIVILEGES', 'TABLESPACE', 'SHOW', 'DESCRIBE', 'EXPLAIN', 'USE', 'CHANGE', 'MODIFY',
  // 事务 / 锁
  'TRANSACTION', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'LOCK', 'UNLOCK', 'TABLES', 'ISOLATION',
  // 类型 / 修饰
  'INT', 'INTEGER', 'SMALLINT', 'BIGINT', 'DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'REAL',
  'CHAR', 'VARCHAR', 'NCHAR', 'NVARCHAR', 'TEXT', 'BLOB', 'DATE', 'TIME', 'TIMESTAMP',
  'DATETIME', 'BOOLEAN', 'BIT', 'BINARY', 'VARBINARY', 'ENUM', 'SERIAL', 'IDENTITY',
  // 其它常用关键字
  'IFS', 'PRAGMA', 'VACUUM', 'ATTACH', 'DETACH', 'EXCEPT', 'INTERSECT', 'MINUS', 'ANY',
  'SOME', 'CASCADE', 'RESTRICT', 'NO', 'ACTION', 'WITH', 'RECURSIVE', 'OVER', 'PARTITION',
  'DENSE_RANK', 'ROW_NUMBER', 'RANK', 'LAG', 'LEAD', 'FIRST_VALUE', 'LAST_VALUE',
  'WINDOW', 'FETCH', 'NEXT', 'ROWS', 'RANGE', 'ONLY', 'DUAL', 'DISTINCT',
]);

export default SQL_KEYWORDS;

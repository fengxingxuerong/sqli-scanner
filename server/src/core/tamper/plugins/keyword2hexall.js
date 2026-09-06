// 关键字 → 十六进制（全部）：将所有 SQL 关键字编码为十六进制（对标 sqlmap keyword2hexall.py）
export const keyword2hexall = {
  name: 'keyword2hexall',
  description: '将所有 SQL 关键字编码为十六进制 0xHEX，绕过 WAF 关键字检测',
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET', 'CREATE', 'DROP', 'ALTER', 'EXEC', 'EXECUTE', 'ALL', 'AS', 'BETWEEN', 'BY', 'CASE', 'CAST', 'CONVERT', 'COUNT', 'DISTINCT', 'ELSE', 'END', 'EXISTS', 'FALSE', 'FOR', 'IF', 'IN', 'IS', 'LIKE', 'NOT', 'NULL', 'OFFSET', 'ON', 'OR', 'ORDER', 'OUTER', 'REPLACE', 'RETURN', 'SELECT', 'SOME', 'TABLE', 'THEN', 'TO', 'TRUE', 'UNION', 'UNIQUE', 'UPDATE', 'USING', 'VALUES', 'WHEN', 'WHERE', 'WITH'];
    let s = String(payload ?? '');
    for (const kw of keywords) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, (match) => {
        const hex = Buffer.from(match.toLowerCase()).toString('hex');
        return `0x${hex}`;
      });
    }
    return s;
  },
};
export default keyword2hexall;
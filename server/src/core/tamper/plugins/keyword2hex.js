// 关键字 → 十六进制：将 SQL 关键字编码为十六进制并通过 0x 前缀表示（对标 sqlmap keyword2hex.py）
// 适用于 WAF 对关键字有严格检测规则的场景
export const keyword2hex = {
  name: 'keyword2hex',
  description: '将 SQL 关键字编码为十六进制 0xHEX 表示，绕过 WAF 关键字检测',
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET', 'CREATE', 'DROP', 'ALTER', 'EXEC', 'EXECUTE'];
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
export default keyword2hex;
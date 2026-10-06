// 关键字 → 十六进制（全部）：将所有 SQL 关键字编码为十六进制（对标 sqlmap keyword2hexall.py）
//
// [2026-10-05 补齐 + 去重] 原列表 62 项里有 7 项重复（OR/ORDER/SELECT/UNION/UPDATE/
// VALUES/WHERE 各出现两次，第二次替换无匹配故无害，但会让"这份覆盖了多少关键字"无法一眼判断），
// 且**漏掉了本仓 payload 真实使用的向量关键字** —— 最要命的是 SLEEP：
// 时间盲注是本仓检出能力的主通道之一（payloads/index.js TIME_VECTORS 全部含 {SLEEP}），
// 而 WAF 对 SLEEP/BENCHMARK 的拦截恰恰最严。tamper 链选中本插件却让 SLEEP 原样发出，
// 等于最贵的那个关键字没被混淆。参照 keywordSplit 的覆盖集补齐（它一直含 SLEEP）。
export const keyword2hexall = {
  name: 'keyword2hexall',
  description: '将所有 SQL 关键字编码为十六进制 0xHEX，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET', 'CREATE', 'DROP', 'ALTER', 'EXEC', 'EXECUTE', 'ALL', 'AS', 'BETWEEN', 'BY', 'CASE', 'CAST', 'CONVERT', 'COUNT', 'DISTINCT', 'ELSE', 'END', 'EXISTS', 'FALSE', 'FOR', 'IF', 'IN', 'IS', 'LIKE', 'NOT', 'NULL', 'OFFSET', 'ON', 'OUTER', 'REPLACE', 'RETURN', 'SOME', 'TABLE', 'THEN', 'TO', 'TRUE', 'UNIQUE', 'USING', 'WHEN', 'WITH', 'SLEEP', 'BENCHMARK', 'CONCAT', 'VERSION', 'DATABASE', 'SCHEMA', 'SUBSTRING', 'LENGTH', 'ASCII', 'EXTRACTVALUE', 'UPDATEXML', 'WAITFOR', 'DELAY', 'PG_SLEEP', 'ROWS', 'TOP'];
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

// 关键字 → 十六进制：将 SQL 关键字编码为十六进制并通过 0x 前缀表示（对标 sqlmap keyword2hex.py）
// 适用于 WAF 对关键字有严格检测规则的场景
//
// [2026-10-05 补齐] 原先 21 个关键字里**没有 SLEEP/BENCHMARK/WAITFOR**，而时间盲注是本仓
// 检出主通道（TIME_VECTORS 全部含 {SLEEP}）且 WAF 对它的拦截最严 —— 最贵的关键字没被混淆。
// 本插件定位是 keyword2hexall 的精简版，故要求 ⊆ keyword2hexall，由
// tests/tamperKeywordCoverage.test.js 钉住这条包含关系与两者的向量关键字覆盖。
export const keyword2hex = {
  name: 'keyword2hex',
  description: '将 SQL 关键字编码为十六进制 0xHEX 表示，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET', 'CREATE', 'DROP', 'ALTER', 'EXEC', 'EXECUTE', 'SLEEP', 'BENCHMARK', 'CONCAT', 'DATABASE', 'SCHEMA', 'VERSION', 'SUBSTRING', 'LENGTH', 'WAITFOR', 'DELAY', 'PG_SLEEP'];
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

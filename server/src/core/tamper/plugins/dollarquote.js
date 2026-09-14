// 对标 sqlmap dollarquote.py：单引号字符串转 PostgreSQL 美元引号
// 'abc' -> $$abc$$，绕过单引号过滤（内容含 $$ 时保持原样避免破坏）
export const dollarquote = {
  name: 'dollarquote',
  description: "将单引号字符串 'x' 转为 PostgreSQL 美元引号 $$x$$（绕过单引号过滤）",
  doctests: [
    { input: "SELECT 'abc' FROM t WHERE x='def'", output: 'SELECT $$abc$$ FROM t WHERE x=$$def$$' },
    { input: "SELECT 'a'='b'", output: 'SELECT $$a$$=$$b$$' },
  ],
  dbms: ['PostgreSQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/'([^']*)'/g, (m, inner) => {
      if (typeof inner === 'string' && inner.includes('$$')) return m;
      return `$$${inner}$$`;
    });
  },
};
export default dollarquote;

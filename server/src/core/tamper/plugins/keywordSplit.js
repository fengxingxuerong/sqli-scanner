// 关键字内插注释分割（类名 keywordSplit）
// 在常见 SQL 关键字中间插入 `/*!*/`，将 `UNION` 拆成 `UNI/*!*/ON`，
// 语义不变但破坏 WAF 对完整关键字的匹配。
const KEYWORDS = [
  'UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY',
  'SLEEP', 'CONCAT', 'VERSION', 'LIKE', 'UPDATE', 'INSERT', 'DROP',
  'CAST', 'GROUP', 'HAVING', 'LIMIT', 'DATABASE', 'SCHEMA',
];

export const keywordSplit = {
  name: 'keywordSplit',
  description: '在 SQL 关键字内部插入 /*!*/ 注释，破坏关键字完整匹配',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let out = payload;
    for (const kw of KEYWORDS) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      out = out.replace(re, (m) => {
        // 从中间（至少偏右 1 字符）切开，避免切出空段
        const mid = Math.max(1, Math.floor(m.length / 2));
        return m.slice(0, mid) + '/*!*/' + m.slice(mid);
      });
    }
    return out;
  },
};

export default keywordSplit;

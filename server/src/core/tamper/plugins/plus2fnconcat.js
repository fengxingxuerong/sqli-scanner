// '+' 拼接 → MsSQL ODBC {fn CONCAT()} 嵌套调用（对标 sqlmap plus2fnconcat.py）
// 改写为左嵌套的 {fn CONCAT({fn CONCAT(a,b)},c)} 形式。
export const plus2fnconcat = {
  name: 'plus2fnconcat',
  description: '将 + 拼接改写为 MsSQL ODBC {fn CONCAT()} 嵌套调用，绕过加号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/('[^']+'|CHAR\(\d+\))\+.*\+('[^']+'|CHAR\(\d+\))/i, (whole) => {
      const parts = [];
      let last = 0;
      let depth = 0;
      let inQuote = false;
      for (let i = 0; i < whole.length; i++) {
        const ch = whole[i];
        if (ch === "'") {
          inQuote = !inQuote;
          continue;
        }
        if (inQuote) continue;
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        else if (ch === '+' && depth === 0) {
          parts.push(whole.slice(last, i));
          last = i + 1;
        }
      }
      parts.push(whole.slice(last));
      let replacement = parts[0];
      for (let i = 1; i < parts.length; i++) {
        replacement = `{fn CONCAT(${replacement},${parts[i]})}`;
      }
      return replacement;
    });
  },
};

export default plus2fnconcat;

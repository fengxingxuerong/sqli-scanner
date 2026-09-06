// '+' 拼接 → MsSQL CONCAT() 函数（对标 sqlmap plus2concat.py）
// 仅改写「字符串字面量 / CHAR(n)」参与的首尾拼接段，顶层 + 换为逗号并包裹 CONCAT()。
export const plus2concat = {
  name: 'plus2concat',
  description: '将 + 拼接改写为 MsSQL CONCAT() 函数，绕过加号过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/('[^']+'|CHAR\(\d+\))\+.*\+('[^']+'|CHAR\(\d+\))/i, (whole) => {
      const chars = [...whole];
      let depth = 0;
      let inQuote = false;
      for (let i = 0; i < chars.length; i++) {
        const ch = chars[i];
        if (ch === "'") {
          inQuote = !inQuote;
          continue;
        }
        if (inQuote) continue;
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        else if (ch === '+' && depth === 0) chars[i] = ',';
      }
      return `CONCAT(${chars.join('')})`;
    });
  },
};

export default plus2concat;

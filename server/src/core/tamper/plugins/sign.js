// 对标 sqlmap sign.py：比较运算符 > 改写为 SIGN() 差值等价形式
// A > B ⟺ SIGN((A)-(B))=1，完全消除 > 运算符（绕过比较符全过滤场景）
// 盲注推断恒为"数值 vs 整数字面量"比较，SIGN 等价精确
export const sign = {
  name: 'sign',
  description: '将 AND/OR 后的 A > B 改写为 SIGN((A)-(B))=1（消除 > 运算符）',
  doctests: [
    { input: '1 AND A > B', output: '1 AND SIGN((A)-(B))=1' },
    { input: '1 AND 5>3', output: '1 AND SIGN((5)-(3))=1' },
    { input: "1 AND name>'a'", output: "1 AND SIGN((name)-('a'))=1" },
    { input: '1 AND 1=1', output: '1 AND 1=1' }, // 无 > 不动
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const s = String(payload ?? '');
    if (!s) return s;
    const m = s.match(/(\b(?:AND|OR)\b\s+)([^><]+?)\s*(?<![<>!])>(?!=)\s*(\w+|'[^']*')/i);
    if (!m) return s;
    return s.replace(m[0], `${m[1]}SIGN((${m[2]})-(${m[3]}))=1`);
  },
};
export default sign;

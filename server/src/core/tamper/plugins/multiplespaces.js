// 在 SQL 关键字后追加额外空格，绕过"关键字紧邻即拦截"类 WAF 规则。
// 仅对常见关键字生效，不影响字符串/数值字面量。
export const multiplespaces = {
  name: 'multiplespaces',
  description: '在 SQL 关键字后追加额外空格，绕过"关键字紧邻即拦截"类规则',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(
      /\b(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|HAVING|LIMIT|INSERT|UPDATE|DELETE|NOT|NULL|LIKE|IN|BETWEEN|GROUP|ASC|DESC)\b/gi,
      (m) => m + ' '
    );
  },
};

export default multiplespaces;

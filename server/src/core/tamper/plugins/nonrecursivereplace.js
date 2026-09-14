// 双写 SQL 关键字（如 OR -> OROR），绕过"关键字命中即删除"类 WAF。
// 若 WAF 执行一次替换（删掉一个 OR），残留正好仍是合法 OR。
export const nonrecursivereplace = {
  name: 'nonrecursivereplace',
  description: '双写 SQL 关键字（如 OR→OROR），绕过"关键字命中即删除"类 WAF',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(
      /\b(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|HAVING|LIMIT|INSERT|UPDATE|DELETE|NOT|NULL|LIKE|IN|BETWEEN|GROUP)\b/gi,
      (m) => m + m
    );
  },
};

export default nonrecursivereplace;

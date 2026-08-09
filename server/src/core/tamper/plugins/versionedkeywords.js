// 将 SQL 关键字用 /*! ... */ 包裹（MySQL 版本条件注释）。
// MySQL 会解析注释内的关键字，而多数 WAF 看到 /*! 直接跳过关键字识别。
export const versionedkeywords = {
  name: 'versionedkeywords',
  description: '将 SQL 关键字用 /*!...*/ 包裹（MySQL 版本条件注释，仅 MySQL 解析内联）',
  transform(payload) {
    return payload.replace(
      /\b(UNION|SELECT|FROM|WHERE|AND|OR|ORDER BY|HAVING|LIMIT|INSERT|UPDATE|DELETE|NOT|NULL|LIKE|IN|BETWEEN|GROUP BY|ASC|DESC)\b/gi,
      (m) => '/*! ' + m + ' */'
    );
  },
};

export default versionedkeywords;

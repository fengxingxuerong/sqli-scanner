// 将 SQL 关键字用 /*! ... */ 包裹（MySQL 版本条件注释）。
// MySQL 会解析注释内的关键字，而多数 WAF 看到 /*! 直接跳过关键字识别。
export const versionedkeywords = {
  name: 'versionedkeywords',
  description: '将 SQL 关键字用 /*!...*/ 包裹（MySQL 版本条件注释，仅 MySQL 解析内联）',
  doctests: [
    { input: 'UNION SELECT', output: '/*! UNION */ /*! SELECT */' },
    // [T-6 2026-10-14] ALL 是 UNION ALL SELECT 的必需组成，上游基础版表含它、本仓漏 ——
    // 漏它属同族内不自洽（examples 反测：上游包 ALL，本仓不包）
    { input: 'UNION ALL SELECT', output: '/*! UNION */ /*! ALL */ /*! SELECT */' },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(
      /\b(UNION|SELECT|ALL|FROM|WHERE|AND|OR|ORDER BY|HAVING|LIMIT|INSERT|UPDATE|DELETE|NOT|NULL|LIKE|IN|BETWEEN|GROUP BY|ASC|DESC)\b/gi,
      (m) => '/*! ' + m + ' */'
    );
  },
};

export default versionedkeywords;

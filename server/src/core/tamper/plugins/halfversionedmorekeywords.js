// MySQL 半版本化注释：/*!50540 KEYWORD*/ 包裹关键字（仅 MySQL 5.5.40+ 执行注释内语法）
const KW =
  'SELECT|UNION|ALL|DISTINCT|FROM|WHERE|AND|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|INSERT|UPDATE|DELETE|INTO|VALUES|SET|DROP|CREATE|TABLE|DATABASE|VERSION|JOIN|ON|BETWEEN|LIKE|NULL|IS|IN|NOT|AS';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const halfversionedmorekeywords = {
  name: 'halfversionedmorekeywords',
  description: '用 /*!50540 KEYWORD*/ 包裹关键字（MySQL 5.5.40+ 执行），绕过 WAF 注释剥离',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(RE, '/*!50540 $1*/');
  },
};

export default halfversionedmorekeywords;

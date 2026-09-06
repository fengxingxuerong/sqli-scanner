// 版本化注释包裹每个关键字（比 versionedkeywords 更激进，覆盖全部常见关键字）
// MySQL 解析 /*! KEYWORD */ 为执行，WAF 可能按普通注释忽略其中的关键字 → 绕过
const KW =
  'SELECT|UNION|ALL|DISTINCT|FROM|WHERE|AND|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|INSERT|UPDATE|DELETE|INTO|VALUES|SET|DROP|CREATE|TABLE|DATABASE|VERSION|JOIN|ON|BETWEEN|LIKE|NULL|IS|IN|NOT|AS';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const versionedmorekeywords = {
  name: 'versionedmorekeywords',
  description: '用 /*! KEYWORD */ 包裹每个关键字，绕过基于关键字的 WAF（MySQL 执行注释内语法）',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  transform(payload) {
    return payload.replace(RE, '/*! $1 */');
  },
};

export default versionedmorekeywords;

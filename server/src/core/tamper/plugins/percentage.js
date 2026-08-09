// 在 MSSQL 关键字字符间插入 %（MSSQL 将 % 视为无操作分隔符）。
// 例如 OR -> O%R、UNION -> U%N%I%O%N；仅对 MSSQL 目标有效（MySQL 不支持该语法）。
export const percentage = {
  name: 'percentage',
  description: '在 MSSQL 关键字字符间插入 %（MSSQL 将 % 视为无操作分隔符）',
  transform(payload) {
    return payload.replace(
      /\b(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|HAVING|LIMIT|INSERT|UPDATE|DELETE|NOT|NULL|LIKE|IN|BETWEEN|GROUP)\b/gi,
      (m) => m.split('').join('%')
    );
  },
};

export default percentage;

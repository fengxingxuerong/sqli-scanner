// SAP 绕过：对 SAP 系统的特定 WAF 绕过（对标 sqlmap sap.py）
// 在关键字之间插入 SAP 特定的注释语法
export const sap = {
  name: 'sap',
  description: 'SAP 系统 WAF 绕过：在关键字之间插入 SAP 特定注释',
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL/**/ECT' : 'sel/**/ect')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN/**/ION' : 'un/**/ion')
      .replace(/\bWHERE\b/gi, (m) => m[0] === 'W' ? 'WH/**/ERE' : 'wh/**/ere');
  },
};
export default sap;
// 空格转 %23%0A（MSSQL 行注释），绕过空格过滤
export const space2mssqlhash = {
  name: 'space2mssqlhash',
  description: '将空格替换为 %23%0A（MSSQL 行注释），绕过空格过滤',
  compat: { dbms: ['SQL Server'] },
  transform(payload) {
    return payload.replace(/ /g, '%23%0A');
  },
};
export default space2mssqlhash;

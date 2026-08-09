// 追加 sp_password 注释，绕过 MSSQL 审计/部分 WAF 对注释前内容的忽略
export const sp_password = {
  name: 'sp_password',
  description: "在 payload 末尾追加 ' sp_password'（MSSQL 注释绕过技巧）",
  transform(payload) {
    return payload + ' sp_password';
  },
};
export default sp_password;

// information_schema 关键字间插注释，绕过基于该库名的 WAF 规则
// ⚠️ 大小写必须**原样保留**：早前用固定小写替换串，把 `INFORMATION_SCHEMA.TABLES` 改成了
//   `information_schema/**/.TABLES` —— MySQL 库名大小写不敏感所以看不出问题，
//   但 Oracle / PostgreSQL 的引用标识符区分大小写，静默改大小写等于换了一个对象名。
export const informationschemacomment = {
  name: 'informationschemacomment',
  description: '在 information_schema 后插入 /**/ 注释（保留原大小写），绕过基于库名的规则',
  doctests: [
    { input: 'SELECT table_name FROM information_schema.tables', output: 'SELECT table_name FROM information_schema/**/.tables' },
    { input: 'SELECT table_name FROM INFORMATION_SCHEMA.TABLES', output: 'SELECT table_name FROM INFORMATION_SCHEMA/**/.TABLES' }, // 上游官方 doctest，大小写原样
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/(information_schema)/gi, '$1/**/');
  },
};
export default informationschemacomment;

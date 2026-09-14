// 空格转 MySQL 接受的空白字符（0x09–0x0D 随机），绕过空格过滤
export const space2mysqlblank = {
  name: 'space2mysqlblank',
  description: '将空格替换为 MySQL 空白字符（%09–%0D 随机选）',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const blanks = ['%09','%0a','%0b','%0c','%0d'];
    return payload.replace(/ /g, () => blanks[Math.floor(Math.random() * blanks.length)]);
  },
};
export default space2mysqlblank;

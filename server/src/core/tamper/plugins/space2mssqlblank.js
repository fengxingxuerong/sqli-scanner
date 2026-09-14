// 空格转 MSSQL 接受的空白控制字符（0x01–0x1F 随机），绕过空格过滤
export const space2mssqlblank = {
  name: 'space2mssqlblank',
  description: '将空格替换为 MSSQL 空白控制字符（%01–%1F 随机选）',
  dbms: ['SQL Server'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const blanks = ['%01','%02','%03','%04','%05','%06','%07','%08','%09','%0a','%0b','%0c','%0d','%0e','%0f','%10','%11','%12','%13','%14','%15','%16','%17','%18','%19','%1a','%1b','%1c','%1d','%1e','%1f'];
    return payload.replace(/ /g, () => blanks[Math.floor(Math.random() * blanks.length)]);
  },
};
export default space2mssqlblank;

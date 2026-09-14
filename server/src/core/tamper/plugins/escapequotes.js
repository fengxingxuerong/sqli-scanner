// 引号前加反斜杠转义，绕过未正确转义的引号过滤
export const escapequotes = {
  name: 'escapequotes',
  description: "将单引号/双引号前加反斜杠转义，绕过引号过滤",
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/'/g, "\\'").replace(/"/g, '\\"');
  },
};
export default escapequotes;

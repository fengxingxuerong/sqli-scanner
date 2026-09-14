// 空格转 # + 随机串 + 换行（MySQL 行注释），绕过空格过滤
export const space2hash = {
  name: 'space2hash',
  description: '将空格替换为 #<随机串>\\n（MySQL 行注释），绕过空格过滤',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/ /g, '#' + Math.random().toString(36).slice(2, 8) + '\n');
  },
};
export default space2hash;

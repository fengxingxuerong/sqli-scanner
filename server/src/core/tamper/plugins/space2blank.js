// 空格转垂直制表符（%0B），绕过空格过滤
export const space2blank = {
  name: 'space2blank',
  description: '将空格替换为垂直制表符 %0b，绕过空格过滤',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/ /g, '%0b');
  },
};
export default space2blank;

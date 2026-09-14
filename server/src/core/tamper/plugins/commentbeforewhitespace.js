// 在空格前插入内联注释，变形关键字-空格分隔
export const commentbeforewhitespace = {
  name: 'commentbeforewhitespace',
  description: '在每个空格前插入 /**/ 注释，变形关键字与空格的分隔结构',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/ /g, '/**/ ');
  },
};
export default commentbeforewhitespace;

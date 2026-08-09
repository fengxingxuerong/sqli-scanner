// 在空格后插入内联注释，变形关键字-空格分隔
export const commentafterwhitespace = {
  name: 'commentafterwhitespace',
  description: '在每个空格后插入 /**/ 注释，变形关键字与空格的分隔结构',
  transform(payload) {
    return payload.replace(/ /g, ' /**/');
  },
};
export default commentafterwhitespace;

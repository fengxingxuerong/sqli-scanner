// 空格转 /**_**/ 多段注释，绕过空格过滤
export const space2morecomment = {
  name: 'space2morecomment',
  description: '将空格替换为 /**_**/ 多段注释，绕过空格过滤',
  transform(payload) {
    return payload.replace(/ /g, '/**_**/');
  },
};
export default space2morecomment;

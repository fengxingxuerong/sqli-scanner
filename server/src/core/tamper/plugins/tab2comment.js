// 制表符转内联注释，绕过基于制表符的解析
export const tab2comment = {
  name: 'tab2comment',
  description: '将制表符 \\t 替换为 /**/ 注释',
  transform(payload) {
    return payload.replace(/\t/g, '/**/');
  },
};
export default tab2comment;

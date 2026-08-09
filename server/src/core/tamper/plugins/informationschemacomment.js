// information_schema 关键字间插注释，绕过基于该库名的 WAF 规则
export const informationschemacomment = {
  name: 'informationschemacomment',
  description: '在 information_schema 后插入 /**/ 注释，绕过基于库名的规则',
  transform(payload) {
    return payload.replace(/information_schema/gi, 'information_schema/**/');
  },
};
export default informationschemacomment;

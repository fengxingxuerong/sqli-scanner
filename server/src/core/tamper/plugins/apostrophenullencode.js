// 单引号转 NULL 前缀编码（%00%27），绕过魔法引号/引号过滤
export const apostrophenullencode = {
  name: 'apostrophenullencode',
  description: "将单引号 ' 替换为 %00%27（NULL 前缀编码），绕过引号过滤",
  transform(payload) {
    return payload.replace(/'/g, '%00%27');
  },
};
export default apostrophenullencode;

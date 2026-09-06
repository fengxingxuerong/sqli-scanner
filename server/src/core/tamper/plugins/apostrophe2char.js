// 单引号转 CHAR(39)，避免字面引号出现在 payload
export const apostrophe2char = {
  name: 'apostrophe2char',
  description: "将单引号 ' 替换为 CHAR(39)，避免字面引号出现在注入串",
  transform(payload) {
    return payload.replace(/'/g, 'CHAR(39)');
  },
};
export default apostrophe2char;

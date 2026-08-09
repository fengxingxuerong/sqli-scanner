// 宽字节绕过 magic_quotes_gpc：单引号 ' 转为 %bf%27（高位字节越过转义）
export const unmagicquotes = {
  name: 'unmagicquotes',
  description: "将 ' 转为 %bf%27 宽字节，绕过 magic_quotes_gpc / addslashes 转义",
  transform(payload) {
    return payload.replace(/'/g, '%bf%27');
  },
};

export default unmagicquotes;

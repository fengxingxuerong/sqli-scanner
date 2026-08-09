// 关键字随机大小写（类名 randomcase）
// 对字母逐个随机化大小写，破坏 WAF 对固定大小写关键字的匹配。
// 注意：随机性使其输出不可预测，测试仅校验其返回字符串且长度不变。
export const randomcase = {
  name: 'randomcase',
  description: '随机化关键字大小写，绕过大小写敏感的关键字过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/[a-zA-Z]/g, (ch) =>
      Math.random() < 0.5 ? ch.toUpperCase() : ch.toLowerCase()
    );
  },
};

export default randomcase;

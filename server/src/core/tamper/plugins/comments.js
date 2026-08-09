// 随机注释注入（类名 comments）
// 在常见 SQL 关键字前插入 `/*! */` 内联注释，扰乱 WAF 的令牌流。
export const comments = {
  name: 'comments',
  description: '在 SQL 关键字前插入 /*! */ 注释，扰乱关键字匹配',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(
      /\b(SELECT|UNION|FROM|WHERE|AND|OR|ORDER|BY|UPDATE|INSERT|DROP|HAVING|GROUP)\b/gi,
      (m) => `/*! */${m}`
    );
  },
};

export default comments;

// 关键字后随机插 /**/ 注释，变形关键字结构（绕过关键字整词规则）
export const randomcomments = {
  name: 'randomcomments',
  description: '在 SELECT/UNION/WHERE/AND/OR/FROM/ORDER/BY 等关键字后插入 /**/ 注释',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/\b(SELECT|UNION|WHERE|AND|OR|FROM|ORDER|BY|LIMIT)\b/gi,
      (m) => m + '/**/');
  },
};
export default randomcomments;

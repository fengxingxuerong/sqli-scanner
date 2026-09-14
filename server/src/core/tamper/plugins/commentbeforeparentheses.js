// 在左括号前插入内联注释，绕过 WAF 对函数调用的检测规则（对标 sqlmap commentbeforeparentheses.py）
// 例如：AND 1=1 → AND 1=1/**/
export const commentbeforeparentheses = {
  name: 'commentbeforeparentheses',
  description: '在左括号前插入内联注释 /**/，绕过 WAF 函数调用检测规则',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\(/g, '/**/(');
  },
};
export default commentbeforeparentheses;

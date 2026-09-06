// 等号 -> LIKE（类名 equaltolike，对齐 sqlmap equaltolike.py）
// [T4] 把 `=` 替换为 ` LIKE `：
//   - 直接拼接（id=1→idLIKE1）产出非法 SQL → 前后补空格；
//   - 复合运算符保护：<=/!=/>=/>=/<> 中的 = 不可拆坏 → (?<![<>!=])=(?!=) 锚点。
export const equaltolike = {
  name: 'equaltolike',
  description: '将等号 = 替换为 LIKE（含 <=/>=/!=/<> 复合运算符保护），等价语义绕过等号过滤',
  doctests: [
    { input: 'id=1', output: 'id LIKE 1' },
    { input: 'a<=1', output: 'a<=1' },
    { input: 'a>=1', output: 'a>=1' },
    { input: 'a<>1', output: 'a<>1' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/(?<![<>!=])=(?!=)/g, ' LIKE ');
  },
};

export default equaltolike;

// 等号 -> RLIKE（类名 equaltorlike，对齐 sqlmap equaltorlike.py）
// [T4 同型缺陷补齐] 兄弟件 equaltolike 已修过这一条（id=1→idLIKE1 产出非法 SQL，
//   前后补空格 + 复合运算符锚点），本件当时漏改：`/=/g` 直换 ⇒ `idRLIKE1` 是非法 SQL，
//   且会把 >=/<=/!= 里的 = 一起拆坏。判据来自上游官方 doctest（verify-tamper-upstream-examples）。
// ⚠️ 已知未做（进本批待办，不在这里顺手改）：与上游一样**不保护字符串字面量** ——
//   `1 AND '1'='1` 会变成 `1 AND '1 RLIKE 1'`，把布尔形态整个改坏；兄弟件 equaltolike 同病。
//   上游也只挡复合运算符、不挡字面量，所以本件对齐上游后仍带这个洞。
export const equaltorlike = {
  name: 'equaltorlike',
  description: '将等号 = 替换为 RLIKE（含 <=/>=/!=/<> 复合运算符保护），等价语义绕过等号过滤',
  doctests: [
    { input: 'SELECT * FROM users WHERE id=1', output: 'SELECT * FROM users WHERE id RLIKE 1' }, // 上游官方示例
    { input: 'id=1', output: 'id RLIKE 1' },
    { input: 'a<=1', output: 'a<=1' },
    { input: 'a>=1', output: 'a>=1' },
    { input: 'a!=1', output: 'a!=1' },
    { input: 'a<>1', output: 'a<>1' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/(?<![<>!=])=(?!=)/g, ' RLIKE ');
  },
};

export default equaltorlike;

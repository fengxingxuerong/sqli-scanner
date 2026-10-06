// [T2 对齐 sqlmap least] 两条分支：
//   - a < b ⟺ LEAST(a,b-1)=a   （本仓既有；上游没有这条）
//   - a > b ⟺ LEAST(a,b+1)=b+1 （上游 least.py 的分支，此前整体缺失 ⇒ 上游示例上原样发出）
// 边界口径：LEAST(a,b)=a ⟺ a<=b，等值会反转，故两式各补 ∓1 保严格等价；
// 复合运算符 <=/>= 不可拆坏 → (?!=) 与 (?<![<>!=]) 锚点显式跳过。
// ⚠️ 已知未做（进本批待办，不在这里顺手改）：上游标注 LEAST() 在 SQLite 不存在
//   （SQLite 用 MIN 重载多参）、SQL Server 2022 才有 ⇒ 本插件尚未声明 dbms 方言限定。
export const least = {
  name: 'least',
  description: '将 a < b 转 LEAST(a,b-1)=a、a > b 转 LEAST(a,b+1)=b+1（±1 语义等价），绕过比较号过滤',
  doctests: [
    { input: 'a<1', output: 'LEAST(a,1-1)=a' },
    { input: 'a<=1', output: 'a<=1' }, // 复合运算符保护
    { input: '1 AND A > B', output: '1 AND LEAST(A,B+1)=B+1' }, // 上游官方 doctest
    { input: 'a>=1', output: 'a>=1' }, // 复合运算符保护
    { input: 'a!=1', output: 'a!=1' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const s = String(payload ?? '');
    const lt = s.replace(/(\w+)\s*<(?!=)\s*(\w+)/g, 'LEAST($1,$2-1)=$1');
    if (lt !== s) return lt;
    return s.replace(/(\w+)\s*(?<![<>!=])>(?!=)\s*(\w+)/g, 'LEAST($1,$2+1)=$2+1');
  },
};

export default least;

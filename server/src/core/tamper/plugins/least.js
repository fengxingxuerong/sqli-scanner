// [T2 对齐 sqlmap least] LEAST(a,b)=a ⟺ a<=b（边界相等语义反转）
// 补 -1：LEAST(a,b-1)=a ⟺ a<b，语义严格等价；跳过复合运算符 <=（`=` 非 \w 天然不匹配，显式断言防回归）
export const least = {
  name: 'least',
  description: '将 a < b 转为 LEAST(a,b-1)=a（-1 语义等价），绕过小于号过滤',
  doctests: [
    { input: 'a<1', output: 'LEAST(a,1-1)=a' },
    { input: 'a<=1', output: 'a<=1' }, // 复合运算符保护
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/(\w+)\s*<(?!=)\s*(\w+)/g, 'LEAST($1,$2-1)=$1');
  },
};

export default least;

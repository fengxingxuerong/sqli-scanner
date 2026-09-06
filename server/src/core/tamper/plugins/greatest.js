// [T1 对齐 sqlmap greatest] GREATEST(a,b)=a ⟺ a>=b（边界相等语义反转）
// 补 +1：GREATEST(a,b+1)=a ⟺ a>b，语义严格等价；跳过复合运算符 >=（`=` 非 \w 天然不匹配，显式断言防回归）
export const greatest = {
  name: 'greatest',
  description: '将 a > b 转为 GREATEST(a,b+1)=a（+1 语义等价），绕过大于号过滤',
  doctests: [
    { input: 'a>1', output: 'GREATEST(a,1+1)=a' },
    { input: 'a>=1', output: 'a>=1' }, // 复合运算符保护
  ],
  transform(payload) {
    return payload.replace(/(\w+)\s*>(?!=)\s*(\w+)/g, 'GREATEST($1,$2+1)=$1');
  },
};

export default greatest;

// 比较符号变形：a > b 转为 GREATEST(a,b)=a（绕过基于 > 的 WAF 规则）
export const greatest = {
  name: 'greatest',
  description: '将 a > b 转为 GREATEST(a,b)=a，绕过大于号过滤',
  transform(payload) {
    return payload.replace(/(\w+)\s*>\s*(\w+)/g, 'GREATEST($1,$2)=$1');
  },
};

export default greatest;

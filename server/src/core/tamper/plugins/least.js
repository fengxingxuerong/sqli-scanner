// 比较符号变形：a < b 转为 LEAST(a,b)=a（绕过基于 < 的 WAF 规则）
export const least = {
  name: 'least',
  description: '将 a < b 转为 LEAST(a,b)=a，绕过小于号过滤',
  transform(payload) {
    return payload.replace(/(\w+)\s*<\s*(\w+)/g, 'LEAST($1,$2)=$1');
  },
};

export default least;

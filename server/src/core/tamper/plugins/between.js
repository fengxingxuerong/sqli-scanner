// 比较符号变形：> 转为 NOT BETWEEN 0 AND；< 转为 BETWEEN 0 AND（绕过基于比较符的 WAF 规则）
export const between = {
  name: 'between',
  description: '将 > 转 NOT BETWEEN 0 AND、< 转 BETWEEN 0 AND，绕过比较符过滤',
  transform(payload) {
    return payload
      .replace(/>/g, ' NOT BETWEEN 0 AND ')
      .replace(/</g, ' BETWEEN 0 AND ');
  },
};

export default between;

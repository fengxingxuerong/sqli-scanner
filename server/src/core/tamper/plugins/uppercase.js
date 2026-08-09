// 将 Payload 全部转为大写，绕过只拦截小写关键字的 WAF。
export const uppercase = {
  name: 'uppercase',
  description: '将 Payload 全部转为大写（绕过只拦截小写关键字的 WAF）',
  transform(payload) {
    return payload.toUpperCase();
  },
};

export default uppercase;

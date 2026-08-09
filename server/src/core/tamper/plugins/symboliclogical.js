// 逻辑运算符 AND/OR 转符号 && / ||，绕过基于关键字的规则
export const symboliclogical = {
  name: 'symboliclogical',
  description: '将 AND 转 &&、OR 转 ||，绕过基于逻辑关键字的规则',
  transform(payload) {
    return payload.replace(/\bAND\b/gi, '&&').replace(/\bOR\b/gi, '||');
  },
};
export default symboliclogical;

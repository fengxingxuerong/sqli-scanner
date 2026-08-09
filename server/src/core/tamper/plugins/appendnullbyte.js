// 追加空字节 %00（部分后端/解析器在 %00 处截断过滤逻辑，绕过后缀检测）
export const appendnullbyte = {
  name: 'appendnullbyte',
  description: '在 payload 末尾追加 %00 空字节，绕过基于后缀匹配的过滤',
  transform(payload) {
    return payload + '%00';
  },
};

export default appendnullbyte;

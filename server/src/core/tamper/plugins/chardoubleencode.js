// 双重 URL 编码：对非常规字符做两次 encodeURIComponent（如空格 %20 → %2520）
export const chardoubleencode = {
  name: 'chardoubleencode',
  description: '对非常规字符做双重 URL 编码，绕过单次解码的 WAF/IDS',
  transform(payload) {
    return payload.replace(/[^A-Za-z0-9]/g, (c) => encodeURIComponent(encodeURIComponent(c)));
  },
};

export default chardoubleencode;

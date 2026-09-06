// HTML 实体解码：将 HTML 实体编码的字符解码为原始字符（对标 sqlmap unhtmlencode.py）
// 适用于 WAF 对 HTML 实体编码有检测规则的场景
export const unhtmlencode = {
  name: 'unhtmlencode',
  description: '将 HTML 实体编码的字符解码为原始字符，绕过 WAF 检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    return src
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#x27;/g, "'")
      .replace(/&#x2F;/g, '/')
      .replace(/&#(\d+);/g, (m, c) => String.fromCharCode(parseInt(c, 10)))
      .replace(/&#x([0-9a-fA-F]+);/g, (m, c) => String.fromCharCode(parseInt(c, 16)));
  },
};
export default unhtmlencode;